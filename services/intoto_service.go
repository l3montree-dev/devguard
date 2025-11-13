package services

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	toto "github.com/in-toto/in-toto-golang/in_toto"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/pkg/errors"
)

type InTotoService struct {
	inTotoLinkRepository  shared.InTotoLinkRepository
	projectRepository     shared.ProjectRepository
	patRepository         shared.PersonalAccessTokenRepository
	supplyChainRepository shared.SupplyChainRepository

	rbacProvider shared.RBACProvider
}

func NewInTotoService(rbacProvider shared.RBACProvider, inTotoLinkRepository shared.InTotoLinkRepository, projectRepository shared.ProjectRepository, patRepository shared.PersonalAccessTokenRepository, supplyChainRepository shared.SupplyChainRepository) *InTotoService {
	return &InTotoService{
		rbacProvider:          rbacProvider,
		inTotoLinkRepository:  inTotoLinkRepository,
		projectRepository:     projectRepository,
		patRepository:         patRepository,
		supplyChainRepository: supplyChainRepository,
	}
}

func (i InTotoService) VerifySupplyChainByDigestOnly(digest string) (bool, error) {
	supplyChains, err := i.supplyChainRepository.FindByDigest(digest)
	if err != nil {
		return false, errors.Wrap(err, "could not find supply chain digests")
	}

	for _, supplyChain := range supplyChains {
		if supplyChain.Verified {
			return true, nil
		}
	}

	return false, nil
}

func (i InTotoService) VerifySupplyChainWithOutputDigest(imageNameOrSupplyChainID string, digest string) (bool, error) {
	var supplyChainID string
	var err error
	// check if it is a supply chain id already
	if strings.Count(imageNameOrSupplyChainID, "-") == 2 {
		// its an image name main-<supplychainid>-<timestamp>
		// get the supply chain id from the image name
		supplyChainID, err = getSupplyChainIDFromImageName(imageNameOrSupplyChainID)
		if err != nil {
			return false, errors.Wrap(err, "could not get supply chain id")
		}
	} else {
		supplyChainID = imageNameOrSupplyChainID
	}

	supplyChains, err := i.supplyChainRepository.FindBySupplyChainID(supplyChainID)
	if err != nil {
		return false, errors.Wrap(err, "could not find supply chain digests")
	}

	for _, supplyChain := range supplyChains {
		if supplyChain.Verified && supplyChain.SupplyChainOutputDigest == digest {
			return true, nil
		}
	}

	return false, nil
}

func (i InTotoService) VerifySupplyChain(supplyChainID string) (bool, error) {

	// get the supply chain links
	supplyChainLinks, err := i.inTotoLinkRepository.FindBySupplyChainID(supplyChainID)
	if err != nil {
		return false, errors.Wrap(err, "could not find supply chain links")
	}

	// get assetID from links
	assetID, err := getAssetIDFromLinks(supplyChainLinks)
	if err != nil {
		return false, errors.Wrap(err, "could not get assetID from links")
	}

	//get projectID and organizationID from assetID
	projectID, organizationID, err := getProjectIDAndOrganizationIDFromAssetID(assetID, i.projectRepository)
	if err != nil {
		return false, errors.Wrap(err, "could not get projectID and organizationID from assetID")
	}

	// get the access control for the organization
	access := i.rbacProvider.GetDomainRBAC(organizationID.String())

	// get all userUuids of the project
	userUuids, err := getProjectUsersID(projectID, access)
	if err != nil {
		return false, errors.Wrap(err, "could not get project users")
	}

	// get all pats which are part of the asset
	pats, err := i.patRepository.FindByUserIDs(userUuids)
	if err != nil {
		return false, errors.Wrap(err, "could not get pats")
	}

	// convert the pats to in-toto keys
	keyIDs, totoKeys, err := i.convertPatsToInTotoKeys(pats)
	if err != nil {
		return false, errors.Wrap(err, "could not convert pats to in-toto keys")
	}

	// create a new layout
	layout := createLayout(keyIDs, totoKeys)

	// generate the the ecdsa key pair and convert them to in-toto keys for signing and verifying the layout
	// it is not very useful here ,but we do need it because the in-toto library requires it
	signKey, layoutKey, err := getIntotoPairKey()
	if err != nil {
		return false, errors.Wrap(err, "could not get in-toto pair key")
	}

	// sign the layout
	err = layout.Sign(signKey)
	if err != nil {
		return false, errors.Wrap(err, "could not sign layout")
	}

	// load the metadata from the layout
	rootLayout, err := loadMetadataFromLayout(layout)
	if err != nil {
		return false, errors.Wrap(err, "could not load metadata")
	}

	// get the dir with the links files
	linkDir, err := createDirWithLinkFiles(supplyChainLinks)
	if err != nil {
		return false, errors.Wrap(err, "could not create dir with link files")
	}

	// defer the removal of the link dir
	defer os.Remove("verify-digest.link")

	// verify the in-toto
	err = verifyInToto(rootLayout, linkDir, layoutKey)
	if err != nil {
		return false, nil
	}

	return true, nil
}

func getSupplyChainIDFromImageName(imageName string) (string, error) {
	// image name regex
	// we expect the image name to be in the format of <registry>/<image>:<tag>[@digest]
	reg := regexp.MustCompile(`^([a-zA-Z0-9.-]+(?:/[a-zA-Z0-9._-]+)+):([a-zA-Z0-9._-]+)(@sha256:[a-f0-9]{64})?$`)
	if !reg.MatchString(imageName) {
		return "", fmt.Errorf("invalid image name")
	}

	//build the supply chain id from the image name
	// <registry>/<image>:<branch>-<commit>-<timestamp>
	imageNameParts := strings.Split(imageName, ":")
	if len(imageNameParts) != 2 {
		return "", fmt.Errorf("invalid image name")
	}

	imageTag := imageNameParts[1]
	imageTagParts := strings.Split(imageTag, "-")
	if len(imageTagParts) < 3 {
		return "", fmt.Errorf("tag does not contain supply chain id")
	}

	supplyChainID := imageTagParts[len(imageTagParts)-2]
	if len(supplyChainID) != 8 {
		return "", fmt.Errorf("tag does not contain supply chain id. Expected 8 characters")
	}

	return supplyChainID, nil
}

func getAssetIDFromLinks(supplyChainLinks []models.InTotoLink) (uuid.UUID, error) {
	// get assetID from links
	if len(supplyChainLinks) == 0 {
		return uuid.Nil, errors.New("no links found")
	}

	assetID := supplyChainLinks[0].AssetID

	return assetID, nil

}

func getProjectIDAndOrganizationIDFromAssetID(assetID uuid.UUID, projectRepository shared.ProjectRepository) (uuid.UUID, uuid.UUID, error) {
	project, err := projectRepository.GetProjectByAssetID(assetID)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}

	return project.ID, project.OrganizationID, nil
}

func getProjectUsersID(projectID uuid.UUID, accessControl shared.AccessControl) ([]uuid.UUID, error) {
	users, err := accessControl.GetAllMembersOfProject(projectID.String())
	if err != nil {
		return nil, errors.Wrap(err, "could not get users")
	}
	userUuids := make([]uuid.UUID, 0, len(users))
	for _, user := range users {
		uuid, err := uuid.Parse(user)
		if err != nil {
			return nil, errors.Wrap(err, "could not parse user id")
		}

		userUuids = append(userUuids, uuid)
	}
	return userUuids, nil
}

func (s InTotoService) convertPatsToInTotoKeys(pats []models.PAT) ([]string, map[string]toto.Key, error) {
	keyIDs := make([]string, len(pats))
	totoKeys := make(map[string]toto.Key)
	for i, pat := range pats {
		key, err := s.HexPublicKeyToInTotoKey(pat.PubKey)
		if err != nil {
			return nil, nil, errors.Wrap(err, "could not convert public key")
		}

		keyIDs[i] = key.KeyID
		totoKeys[key.KeyID] = key
	}
	return keyIDs, totoKeys, nil
}

func createLayout(keyIDs []string, totoKeys map[string]toto.Key) *toto.Metablock {
	t := time.Now()
	t = t.Add(30 * 24 * time.Hour)
	return &toto.Metablock{
		Signed: toto.Layout{
			Type:    "layout",
			Expires: t.Format("2006-01-02T15:04:05Z"),
			Steps: []toto.Step{
				{
					Type:    "step",
					PubKeys: keyIDs,
					SupplyChainItem: toto.SupplyChainItem{
						Name:              "post-commit",
						ExpectedMaterials: [][]string{{"ALLOW", "*"}}, // there is no way we can know what the materials are
						ExpectedProducts:  [][]string{{"ALLOW", "*"}},
					},
				},
				{
					Type:    "step",
					PubKeys: keyIDs,
					SupplyChainItem: toto.SupplyChainItem{
						Name:              "build",
						ExpectedMaterials: [][]string{{"MATCH", "*", "WITH", "PRODUCTS", "FROM", "post-commit"}, {"DISALLOW", "*"}}, // we expect the post-commit step to
						ExpectedProducts:  [][]string{{"ALLOW", "*"}},
					},
				},
				{
					Type:    "step",
					PubKeys: keyIDs,
					SupplyChainItem: toto.SupplyChainItem{
						Name:              "deploy",
						ExpectedMaterials: [][]string{{"MATCH", "*", "WITH", "PRODUCTS", "FROM", "build"}, {"DISALLOW", "*"}},
						ExpectedProducts:  [][]string{{"REQUIRE", "image-digest.txt"}, {"ALLOW", "*"}},
					},
				},
			},
			Inspect: []toto.Inspection{
				{
					// just do nothing - we will prepare the folders beforehand
					Run:  []string{"true"},
					Type: "inspection",
					SupplyChainItem: toto.SupplyChainItem{
						Name:              "verify-digest",
						ExpectedMaterials: [][]string{{"ALLOW", "*"}},
						ExpectedProducts: [][]string{
							{"REQUIRE", "image-digest.txt"},
							{"MATCH", "image-digest.txt", "WITH", "PRODUCTS", "FROM", "deploy"}, // makes sure image-digest.txt is the same as the created digest
							// {"DISALLOW", "image-digest.txt"},
						},
					},
				},
			},
			Keys: totoKeys,
		},
	}

}

func verifyInToto(rootLayout toto.Metadata, linkDir string, layoutKey toto.Key) error {
	_, err := toto.InTotoVerify(rootLayout, map[string]toto.Key{
		layoutKey.KeyID: layoutKey,
	}, linkDir, "", nil, nil, true)
	if err != nil {
		return errors.Wrap(err, "could not verify in-toto")
	}

	return err
}

func getIntotoPairKey() (toto.Key, toto.Key, error) {
	// generate the ecdsa key pair for signing and verifying the layout
	privateKey, publicKey, err := generateECDSAKey()
	if err != nil {
		return toto.Key{}, toto.Key{}, errors.Wrap(err, "could not generate key pair")
	}

	// convert the private key to in-toto key for signing the layout
	signKey, err := privateKeyToInTotoKey(privateKey)
	if err != nil {
		return toto.Key{}, toto.Key{}, errors.Wrap(err, "could not convert private key to in-toto key")
	}

	// convert the public key to in-toto key for verifying the layout
	layoutKey, err := publicKeyToInTotoKey(publicKey)
	if err != nil {
		return toto.Key{}, toto.Key{}, errors.Wrap(err, "could not convert public key to in-toto key")
	}
	return signKey, layoutKey, nil
}

func generateECDSAKey() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return nil, nil, errors.Wrap(err, "could not generate key")
	}
	// get the public key
	publicKey := privateKey.Public().(*ecdsa.PublicKey)

	return privateKey, publicKey, nil

}

func privateKeyToInTotoKey(privateKey *ecdsa.PrivateKey) (toto.Key, error) {
	// marshal
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return toto.Key{}, errors.Wrap(err, "failed to marshal private key")
	}
	// encode to pem
	b := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// create new reader
	reader := bytes.NewReader(b)

	var key toto.Key
	err = key.LoadKeyReader(reader, "ecdsa-sha2-nistp521", []string{"sha256"})
	if err != nil {
		return toto.Key{}, errors.Wrap(err, "failed to load key")
	}

	return key, nil
}

func publicKeyToInTotoKey(publicKey *ecdsa.PublicKey) (toto.Key, error) {
	// marshal
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return toto.Key{}, errors.Wrap(err, "failed to marshal public key")
	}

	// encode to pem
	b := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	// create new reader
	reader := bytes.NewReader(b)

	var key toto.Key
	err = key.LoadKeyReader(reader, "ecdsa-sha2-nistp521", []string{"sha256"})
	if err != nil {
		return toto.Key{}, errors.Wrap(err, "failed to load key")
	}
	return key, nil
}

func (InTotoService) HexPublicKeyToInTotoKey(hexPubKey string) (toto.Key, error) {
	ecdsaPubKey := HexPubKeyToECDSA(hexPubKey)
	return publicKeyToInTotoKey(&ecdsaPubKey)
}

func loadMetadataFromLayout(layout *toto.Metablock) (toto.Metadata, error) {
	// create a tmp file for the layout
	tmpfile, err := os.CreateTemp("", "root.layout.json")
	if err != nil {
		return nil, errors.Wrap(err, "could not create temp file")
	}

	// dump the layout
	err = layout.Dump(tmpfile.Name())
	if err != nil {
		return nil, errors.Wrap(err, "could not dump layout")
	}

	// load the metadata from the dumped layout
	return toto.LoadMetadata(tmpfile.Name())

}

func createDirWithLinkFiles(supplyChainLinks []models.InTotoLink) (string, error) {
	// create a temp dir for the links
	linkDir, err := os.MkdirTemp("", "links")
	if err != nil {
		return "", errors.Wrap(err, "could not create temp dir")
	}

	// create the links
	for _, link := range supplyChainLinks {
		// make file from link
		err = os.WriteFile(fmt.Sprintf("%s/%s", linkDir, link.Filename), []byte(link.Payload), 0600)
		if err != nil {
			return "", errors.Wrap(err, "could not write file")
		}
	}

	return linkDir, nil
}
