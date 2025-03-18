package utils_test

import (
	"testing"

	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestGetAssetVersionInfoFromGit(t *testing.T) {

	t.Run("it should return error if cannot mark as safe path", func(t *testing.T) {
		mocksgitLister := mocks.UtilsGitLister{}
		mocksgitLister.On("MarkAsSafePath", ".").Return(errors.New("cannot mark as safe path"))

		_, err := utils.GetAssetVersionInfoFromGit(&mocksgitLister, ".")
		assert.Error(t, err)
	})

	t.Run("it should return error if cannot get tags", func(t *testing.T) {
		mocksgitLister := mocks.UtilsGitLister{}
		mocksgitLister.On("MarkAsSafePath", ".").Return(nil)
		mocksgitLister.On("GetTags", ".").Return([]string{"1.0.0"}, errors.New("cannot get tags"))
		mocksgitLister.On("GetBranchName", ".").Return("", nil)
		mocksgitLister.On("GetDefaultBranchName", ".").Return("", nil)

		_, err := utils.GetAssetVersionInfoFromGit(&mocksgitLister, ".")
		assert.Error(t, err)
	})

	t.Run("it should return the default version if no tags are found", func(t *testing.T) {
		mocksgitLister := mocks.UtilsGitLister{}
		mocksgitLister.On("MarkAsSafePath", ".").Return(nil)
		mocksgitLister.On("GetTags", ".").Return([]string{""}, nil)
		mocksgitLister.On("GitCommitCount", ".", mock.Anything).Return(0, nil)
		mocksgitLister.On("GetBranchName", ".").Return("", nil)
		mocksgitLister.On("GetDefaultBranchName", ".").Return("", nil)

		versionInfo, err := utils.GetAssetVersionInfoFromGit(&mocksgitLister, ".")

		assert.NoError(t, err)
		assert.Equal(t, "0.0.0", versionInfo.Version)

	})

	t.Run("it should return the default version if no tags are found, with the count of commits", func(t *testing.T) {
		mocksgitLister := mocks.UtilsGitLister{}
		mocksgitLister.On("MarkAsSafePath", ".").Return(nil)
		mocksgitLister.On("GetTags", ".").Return([]string{""}, nil)
		mocksgitLister.On("GitCommitCount", ".", mock.Anything).Return(5, nil)
		mocksgitLister.On("GetBranchName", ".").Return("", nil)
		mocksgitLister.On("GetDefaultBranchName", ".").Return("", nil)

		versionInfo, err := utils.GetAssetVersionInfoFromGit(&mocksgitLister, ".")

		assert.NoError(t, err)
		assert.Equal(t, "0.0.0-5", versionInfo.Version)

	})

	t.Run("it should return the default version if no valid tags are found", func(t *testing.T) {
		mocksgitLister := mocks.UtilsGitLister{}
		mocksgitLister.On("MarkAsSafePath", ".").Return(nil)
		mocksgitLister.On("GetTags", ".").Return([]string{"NotAVersionTag"}, nil)
		mocksgitLister.On("GitCommitCount", ".", mock.Anything).Return(0, nil)
		mocksgitLister.On("GetBranchName", ".").Return("", nil)
		mocksgitLister.On("GetDefaultBranchName", ".").Return("", nil)

		versionInfo, err := utils.GetAssetVersionInfoFromGit(&mocksgitLister, ".")

		assert.NoError(t, err)
		assert.Equal(t, "0.0.0", versionInfo.Version)

	})

	t.Run("it should return the tag version if a tag is found", func(t *testing.T) {
		mocksgitLister := mocks.UtilsGitLister{}
		mocksgitLister.On("MarkAsSafePath", ".").Return(nil)
		mocksgitLister.On("GetTags", ".").Return([]string{"v1.0.0"}, nil)
		mocksgitLister.On("GitCommitCount", ".", mock.Anything).Return(0, nil)
		mocksgitLister.On("GetBranchName", ".").Return("", nil)
		mocksgitLister.On("GetDefaultBranchName", ".").Return("", nil)

		versionInfo, err := utils.GetAssetVersionInfoFromGit(&mocksgitLister, ".")

		assert.NoError(t, err)
		assert.Equal(t, "1.0.0", versionInfo.Version)

	})

	t.Run("it should return the tag version if a tag is found, with the count of commits", func(t *testing.T) {
		mocksgitLister := mocks.UtilsGitLister{}
		mocksgitLister.On("MarkAsSafePath", ".").Return(nil)
		mocksgitLister.On("GetTags", ".").Return([]string{"v1.0.0"}, nil)
		mocksgitLister.On("GitCommitCount", ".", mock.Anything).Return(5, nil)
		mocksgitLister.On("GetBranchName", ".").Return("", nil)
		mocksgitLister.On("GetDefaultBranchName", ".").Return("", nil)

		versionInfo, err := utils.GetAssetVersionInfoFromGit(&mocksgitLister, ".")

		assert.NoError(t, err)
		assert.Equal(t, "1.0.0-5", versionInfo.Version)

	})

	t.Run("it shouldss return the latest tag version if multiple tags are found", func(t *testing.T) {
		mocksgitLister := mocks.UtilsGitLister{}
		mocksgitLister.On("MarkAsSafePath", ".").Return(nil)
		mocksgitLister.On("GetTags", ".").Return([]string{"v1.0.0", "v1.0.5", "v2.0.9"}, nil)
		mocksgitLister.On("GitCommitCount", ".", mock.Anything).Return(0, nil)
		mocksgitLister.On("GetBranchName", ".").Return("", nil)
		mocksgitLister.On("GetDefaultBranchName", ".").Return("", nil)

		versionInfo, err := utils.GetAssetVersionInfoFromGit(&mocksgitLister, ".")

		assert.NoError(t, err)
		assert.Equal(t, "2.0.9", versionInfo.Version)

	})

	t.Run("it should return the latest tag version if multiple tags are found, tags do not start with 'v'", func(t *testing.T) {
		mocksgitLister := mocks.UtilsGitLister{}
		mocksgitLister.On("MarkAsSafePath", ".").Return(nil)
		mocksgitLister.On("GetTags", ".").Return([]string{"1.0.0", "1.0.5", "2.0.9"}, nil)
		mocksgitLister.On("GitCommitCount", ".", mock.Anything).Return(0, nil)
		mocksgitLister.On("GetBranchName", ".").Return("", nil)
		mocksgitLister.On("GetDefaultBranchName", ".").Return("", nil)

		versionInfo, err := utils.GetAssetVersionInfoFromGit(&mocksgitLister, ".")

		assert.NoError(t, err)
		assert.Equal(t, "2.0.9", versionInfo.Version)

	})

	t.Run("it should return the valid tag version if multiple tags are found", func(t *testing.T) {
		mocksgitLister := mocks.UtilsGitLister{}
		mocksgitLister.On("MarkAsSafePath", ".").Return(nil)
		mocksgitLister.On("GetTags", ".").Return([]string{"blaBla", "1.0.5", "NOTag"}, nil)
		mocksgitLister.On("GitCommitCount", ".", mock.Anything).Return(0, nil)
		mocksgitLister.On("GetBranchName", ".").Return("", nil)
		mocksgitLister.On("GetDefaultBranchName", ".").Return("", nil)

		versionInfo, err := utils.GetAssetVersionInfoFromGit(&mocksgitLister, ".")

		assert.NoError(t, err)
		assert.Equal(t, "1.0.5", versionInfo.Version)

	})

	t.Run("it should return branch name if no tags are found but commits are present", func(t *testing.T) {
		mocksgitLister := mocks.UtilsGitLister{}
		mocksgitLister.On("MarkAsSafePath", ".").Return(nil)
		mocksgitLister.On("GetTags", ".").Return([]string{}, nil)
		mocksgitLister.On("GitCommitCount", ".", mock.Anything).Return(5, nil)
		mocksgitLister.On("GetBranchName", ".").Return("main", nil)
		mocksgitLister.On("GetDefaultBranchName", ".").Return("main", nil)

		versionInfo, err := utils.GetAssetVersionInfoFromGit(&mocksgitLister, ".")

		assert.NoError(t, err)
		assert.Equal(t, "0.0.0-5", versionInfo.Version)
		assert.Equal(t, "main", versionInfo.BranchOrTag)

	})

	t.Run("it should return branch name if there are tags are found but also commits are present", func(t *testing.T) {
		mocksgitLister := mocks.UtilsGitLister{}
		mocksgitLister.On("MarkAsSafePath", ".").Return(nil)
		mocksgitLister.On("GetTags", ".").Return([]string{"1.0.0"}, nil)
		mocksgitLister.On("GitCommitCount", ".", mock.Anything).Return(5, nil)
		mocksgitLister.On("GetBranchName", ".").Return("main", nil)
		mocksgitLister.On("GetDefaultBranchName", ".").Return("main", nil)

		versionInfo, err := utils.GetAssetVersionInfoFromGit(&mocksgitLister, ".")

		assert.NoError(t, err)
		assert.Equal(t, "1.0.0-5", versionInfo.Version)
		assert.Equal(t, "main", versionInfo.BranchOrTag)
		assert.Equal(t, "main", versionInfo.DefaultBranch)

	})

	t.Run("it should return the tag as branch name if there are not any commits present", func(t *testing.T) {
		mocksgitLister := mocks.UtilsGitLister{}
		mocksgitLister.On("MarkAsSafePath", ".").Return(nil)
		mocksgitLister.On("GetTags", ".").Return([]string{}, nil)
		mocksgitLister.On("GitCommitCount", ".", mock.Anything).Return(0, nil)
		mocksgitLister.On("GetBranchName", ".").Return("main", nil)
		mocksgitLister.On("GetDefaultBranchName", ".").Return("main", nil)

		versionInfo, err := utils.GetAssetVersionInfoFromGit(&mocksgitLister, ".")

		assert.NoError(t, err)
		assert.Equal(t, "0.0.0", versionInfo.Version)
		assert.Equal(t, "0.0.0", versionInfo.BranchOrTag)
		assert.Equal(t, "main", versionInfo.DefaultBranch)

	})

	t.Run("it should return the right default branch name", func(t *testing.T) {
		mocksgitLister := mocks.UtilsGitLister{}
		mocksgitLister.On("MarkAsSafePath", ".").Return(nil)
		mocksgitLister.On("GetTags", ".").Return([]string{}, nil)
		mocksgitLister.On("GitCommitCount", ".", mock.Anything).Return(0, nil)
		mocksgitLister.On("GetBranchName", ".").Return("main", nil)
		mocksgitLister.On("GetDefaultBranchName", ".").Return("NOTmain", nil)

		versionInfo, err := utils.GetAssetVersionInfoFromGit(&mocksgitLister, ".")

		assert.NoError(t, err)
		assert.Equal(t, "0.0.0", versionInfo.Version)
		assert.Equal(t, "0.0.0", versionInfo.BranchOrTag)
		assert.Equal(t, "NOTmain", versionInfo.DefaultBranch)

	})

}
