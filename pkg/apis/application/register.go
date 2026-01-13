package application

const (
	// API Group
	Group string = "argoproj.io"

	// Application constants
	ApplicationKind      string = "Application"
	ApplicationSingular  string = "application"
	ApplicationPlural    string = "applications"
	ApplicationShortName string = "app"
	ApplicationFullName  string = ApplicationPlural + "." + Group

	// AppProject constants
	AppProjectKind      string = "AppProject"
	AppProjectSingular  string = "appproject"
	AppProjectPlural    string = "appprojects"
	AppProjectShortName string = "appproject"
	AppProjectFullName  string = AppProjectPlural + "." + Group

	// ApplicationSet constants
	ApplicationSetKind      string = "ApplicationSet"
	ApplicationSetSingular  string = "applicationset"
	ApplicationSetShortName string = "appset"
	ApplicationSetPlural    string = "applicationsets"
	ApplicationSetFullName  string = ApplicationSetPlural + "." + Group

	// Repository constants
	RepositoryKind      string = "Repository"
	RepositorySingular  string = "repository"
	RepositoryShortName string = "repo"
	RepositoryPlural    string = "repositories"
	RepositoryFullName  string = RepositoryPlural + "." + Group

	// RepositoryCredentials constants
	RepositoryCredentialsKind      string = "RepositoryCredentials"
	RepositoryCredentialsSingular  string = "repositorycredentials"
	RepositoryCredentialsShortName string = "repocreds"
	RepositoryCredentialsPlural    string = "repositorycredentials"
	RepositoryCredentialsFullName  string = RepositoryCredentialsPlural + "." + Group
)
