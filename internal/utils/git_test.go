package utils_test

import (
	"testing"

	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func setEmptyEnvVars(t *testing.T) {
	// Clear the environment variables to avoid conflicts
	t.Setenv("CI_COMMIT_REF_NAME", "")
	t.Setenv("CI_DEFAULT_BRANCH", "")
	t.Setenv("CI_COMMIT_TAG", "")
	t.Setenv("GITHUB_REF_NAME", "")
	t.Setenv("GITHUB_BASE_REF", "")
}

func TestGetAssetVersionInfo(t *testing.T) {
	setEmptyEnvVars(t)

	t.Run("it should return error if cannot get tags", func(t *testing.T) {
		mocksgitLister := mocks.GitLister{}
		utils.GitLister = &mocksgitLister
		mocksgitLister.On("GetTags", ".").Return([]string{"1.0.0"}, errors.New("cannot get tags"))
		mocksgitLister.On("GetBranchName", ".").Return("", nil)
		mocksgitLister.On("GetDefaultBranchName", ".").Return("", nil)

		_, err := utils.GetAssetVersionInfo(".")
		assert.Error(t, err)
	})

	t.Run("it should return the tag version if a tag is found", func(t *testing.T) {
		mocksgitLister := mocks.GitLister{}
		utils.GitLister = &mocksgitLister
		mocksgitLister.On("GetTags", ".").Return([]string{"v1.0.0"}, nil)
		mocksgitLister.On("GitCommitCount", ".", mock.Anything).Return(0, nil)
		mocksgitLister.On("GetBranchName", ".").Return("", nil)
		mocksgitLister.On("GetDefaultBranchName", ".").Return("", nil)

		versionInfo, err := utils.GetAssetVersionInfo(".")

		assert.NoError(t, err)
		assert.Equal(t, "1.0.0", versionInfo.BranchOrTag)

	})

	t.Run("it should return the latest tag version if multiple tags are found", func(t *testing.T) {
		mocksgitLister := mocks.GitLister{}
		utils.GitLister = &mocksgitLister

		mocksgitLister.On("GetTags", ".").Return([]string{"v1.0.0", "v1.0.5", "v2.0.9"}, nil)
		mocksgitLister.On("GitCommitCount", ".", mock.Anything).Return(0, nil)
		mocksgitLister.On("GetBranchName", ".").Return("", nil)
		mocksgitLister.On("GetDefaultBranchName", ".").Return("", nil)

		versionInfo, err := utils.GetAssetVersionInfo(".")

		assert.NoError(t, err)
		assert.Equal(t, "2.0.9", versionInfo.BranchOrTag)

	})

	t.Run("it should return the latest tag version if multiple tags are found, tags do not start with 'v'", func(t *testing.T) {
		mocksgitLister := mocks.GitLister{}
		utils.GitLister = &mocksgitLister

		mocksgitLister.On("GetTags", ".").Return([]string{"1.0.0", "1.0.5", "2.0.9"}, nil)
		mocksgitLister.On("GitCommitCount", ".", mock.Anything).Return(0, nil)
		mocksgitLister.On("GetBranchName", ".").Return("", nil)
		mocksgitLister.On("GetDefaultBranchName", ".").Return("", nil)

		versionInfo, err := utils.GetAssetVersionInfo(".")

		assert.NoError(t, err)
		assert.Equal(t, "2.0.9", versionInfo.BranchOrTag)
	})

	t.Run("it should return the valid tag version if multiple tags are found", func(t *testing.T) {
		mocksgitLister := mocks.GitLister{}
		utils.GitLister = &mocksgitLister

		mocksgitLister.On("GetTags", ".").Return([]string{"blaBla", "1.0.5", "NOTag"}, nil)
		mocksgitLister.On("GitCommitCount", ".", mock.Anything).Return(0, nil)
		mocksgitLister.On("GetBranchName", ".").Return("", nil)
		mocksgitLister.On("GetDefaultBranchName", ".").Return("", nil)

		versionInfo, err := utils.GetAssetVersionInfo(".")

		assert.NoError(t, err)
		assert.Equal(t, "1.0.5", versionInfo.BranchOrTag)
	})

	t.Run("it should return branch name if no tags are found but commits are present", func(t *testing.T) {
		mocksgitLister := mocks.GitLister{}
		utils.GitLister = &mocksgitLister

		mocksgitLister.On("GetTags", ".").Return([]string{}, nil)
		mocksgitLister.On("GitCommitCount", ".", mock.Anything).Return(5, nil)
		mocksgitLister.On("GetBranchName", ".").Return("main", nil)
		mocksgitLister.On("GetDefaultBranchName", ".").Return("main", nil)

		versionInfo, err := utils.GetAssetVersionInfo(".")

		assert.NoError(t, err)

		assert.Equal(t, "main", versionInfo.BranchOrTag)

	})

	t.Run("it should return branch name if there are tags are found but also commits are present", func(t *testing.T) {
		mocksgitLister := mocks.GitLister{}
		utils.GitLister = &mocksgitLister

		mocksgitLister.On("GetTags", ".").Return([]string{"1.0.0"}, nil)
		mocksgitLister.On("GitCommitCount", ".", mock.Anything).Return(5, nil)
		mocksgitLister.On("GetBranchName", ".").Return("main", nil)
		mocksgitLister.On("GetDefaultBranchName", ".").Return("main", nil)

		versionInfo, err := utils.GetAssetVersionInfo(".")

		assert.NoError(t, err)

		assert.Equal(t, "main", versionInfo.BranchOrTag)
		assert.Equal(t, "main", versionInfo.DefaultBranch)

	})

	t.Run("it should return the tag as branch name if there are not any commits present", func(t *testing.T) {
		mocksgitLister := mocks.GitLister{}
		utils.GitLister = &mocksgitLister

		mocksgitLister.On("GetTags", ".").Return([]string{}, nil)
		mocksgitLister.On("GitCommitCount", ".", mock.Anything).Return(0, nil)
		mocksgitLister.On("GetBranchName", ".").Return("main", nil)
		mocksgitLister.On("GetDefaultBranchName", ".").Return("main", nil)

		versionInfo, err := utils.GetAssetVersionInfo(".")

		assert.NoError(t, err)

		assert.Equal(t, "0.0.0", versionInfo.BranchOrTag)
		assert.Equal(t, "main", versionInfo.DefaultBranch)

	})

	t.Run("it should return the right default branch name", func(t *testing.T) {
		mocksgitLister := mocks.GitLister{}
		utils.GitLister = &mocksgitLister

		mocksgitLister.On("GetTags", ".").Return([]string{}, nil)
		mocksgitLister.On("GitCommitCount", ".", mock.Anything).Return(0, nil)
		mocksgitLister.On("GetBranchName", ".").Return("main", nil)
		mocksgitLister.On("GetDefaultBranchName", ".").Return("NOTmain", nil)

		versionInfo, err := utils.GetAssetVersionInfo(".")

		assert.NoError(t, err)

		assert.Equal(t, "0.0.0", versionInfo.BranchOrTag)
		assert.Equal(t, "NOTmain", versionInfo.DefaultBranch)

	})

	t.Run("it should also here return the right default branch name", func(t *testing.T) {
		mocksgitLister := mocks.GitLister{}
		utils.GitLister = &mocksgitLister

		mocksgitLister.On("GetTags", ".").Return([]string{}, nil)
		mocksgitLister.On("GitCommitCount", ".", mock.Anything).Return(0, nil)
		mocksgitLister.On("GetBranchName", ".").Return("main", nil)
		mocksgitLister.On("GetDefaultBranchName", ".").Return(`NOTmain`, nil)

		versionInfo, err := utils.GetAssetVersionInfo(".")

		assert.NoError(t, err)
		assert.Equal(t, "0.0.0", versionInfo.BranchOrTag)
		assert.Equal(t, "NOTmain", versionInfo.DefaultBranch)

	})

	t.Run("it should read the branch name from the environment variable CI_COMMIT_REF_NAME", func(t *testing.T) {
		mocksgitLister := mocks.GitLister{}
		utils.GitLister = &mocksgitLister

		mocksgitLister.On("GetTags", ".").Return([]string{}, nil)
		mocksgitLister.On("GitCommitCount", ".", mock.Anything).Return(5, nil)
		mocksgitLister.On("GetDefaultBranchName", ".").Return("", nil)

		// Set the environment variable for the default branch name
		t.Setenv("CI_COMMIT_REF_NAME", "test")

		versionInfo, err := utils.GetAssetVersionInfo(".")

		assert.NoError(t, err)
		assert.Equal(t, "test", versionInfo.BranchOrTag)

	})

	t.Run("it should read the branch name from the environment variable GITHUB_REF_NAME", func(t *testing.T) {
		mocksgitLister := mocks.GitLister{}
		utils.GitLister = &mocksgitLister

		mocksgitLister.On("GetTags", ".").Return([]string{}, nil)
		mocksgitLister.On("GitCommitCount", ".", mock.Anything).Return(5, nil)
		mocksgitLister.On("GetDefaultBranchName", ".").Return("", nil)

		// Set the environment variable for the default branch name
		t.Setenv("GITHUB_REF_NAME", "test")

		versionInfo, err := utils.GetAssetVersionInfo(".")

		assert.NoError(t, err)
		assert.Equal(t, "test", versionInfo.BranchOrTag)

	})

}
