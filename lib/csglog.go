package lib

type CsgLogWeb struct {
	DateTime             string `json:"DateTime,omitempty"`
	RiskClass            string `json:"RiskClass,omitempty"`    //
	Action               string `json:"Action,omitempty"`       //
	User                 string `json:"User,omitempty"`         //
	PolicyName           string `json:"PolicyName,omitempty"`   //
	CategoryName         string `json:"CategoryName,omitempty"` //
	Domain               string `json:"Domain,omitempty"`       //
	URLFull              string `json:"URLFull,omitempty"`      //
	CloudAppName         string `json:"CloudAppName,omitempty"` //
	CloudAppForwarded    string `json:"CloudAppForwarded,omitempty"`
	CloudAppRiskLevel    string `json:"CloudAppRiskLevel,omitempty"` //
	ConnectionIP         string `json:"ConnectionIP,omitempty"`      //
	ConnectionIPCountry  string `json:"Connection IP Country,omitempty"`
	DestinationIP        string `json:"DestinationIP,omitempty"` //
	SourceIP             string `json:"SourceIP,omitempty"`      //
	AnalyticName         string `json:"AnalyticName,omitempty"`
	FileSandboxStatus    string `json:"FileSandboxStatus,omitempty"`
	Severity             string `json:"Severity,omitempty"` //
	ThreatType           string `json:"ThreatType,omitempty"`
	FileName             string `json:"FileName,omitempty"` //
	FileType             string `json:"FileType,omitempty"` //
	ReferrerURLFull      string `json:"ReferrerURLFull,omitempty"`
	UserAgent            string `json:"UserAgent,omitempty"` //
	AuthenticationMethod string `json:"AuthenticationMethod,omitempty"`
	FilteringSource      string `json:"FilteringSource,omitempty"`
	HTTPStatusCode       string `json:"HTTPStatusCode,omitempty"`
	Port                 string `json:"Port,omitempty"`
	BytesReceived        string `json:"BytesReceived,omitempty"` //
	BytesSent            string `json:"BytesSent,omitempty"`     //
	Protocol             string `json:"Protocol,omitempty"`      //
	RequestMethod        string `json:"RequestMethod,omitempty"` //
	DataCenter           string `json:"DataCenter,omitempty"`    //
}

type CsgLogEmail struct {
	DateTime             string `json:"DateTime,omitempty"`
	RecipientAddress     string `json:"RecipientAddress,omitempty"`
	Subject              string `json:"Subject,omitempty"`
	Action               string `json:"Action,omitempty"`
	BlackWhitelisted     string `json:"BlackWhitelisted,omitempty"`
	BlockedAttachmentExt string `json:"BlockedAttachmentExt,omitempty"`
	SenderIP             string `json:"SenderIP,omitempty"`
	SenderIPCountry      string `json:"SenderIPCountry,omitempty"`
	AdvancedEncryption   string `json:"AdvancedEncryption,omitempty"`
	VirusName            string `json:"VirusName,omitempty"`
	Direction            string `json:"Direction,omitempty"`
	FromAddress          string `json:"FromAddress,omitempty"`
	PolicyName           string `json:"PolicyName,omitempty"`
	RecipientDomain      string `json:"RecipientDomain,omitempty"`
	SenderName           string `json:"SenderName,omitempty"`
	FilteringReason      string `json:"FilteringReason,omitempty"`
	AttachmentFilename   string `json:"AttachmentFilename,omitempty"`
	AttachmentFileType   string `json:"AttachmentFileType,omitempty"`
	EmbURLRiskClass      string `json:"RecipientAddress,omitempty"`
	EmbURLSeverity       string `json:"EmbURLSeverity,omitempty"`
	SpamScore            string `json:"SpamScore,omitempty"`
	MessageSize          string `json:"MessageSize,omitempty"`
	AttachmentSize       string `json:"AttachmentSize,omitempty"`
}
