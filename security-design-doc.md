# セキュリティ要件

## TechNova社120アカウント構成における包括的セキュリティアーキテクチャ

### 1. 全体セキュリティ戦略とコンプライアンス要件

#### セキュリティ設計原則

**Zero Trust アーキテクチャの採用**
- すべてのネットワークトラフィック、ユーザーアクセス、デバイス接続を検証します。従来の境界防御モデルから脱却し、「信頼せず、常に検証する」原則を徹底適用することで、内部脅威やラテラルムーブメントのリスクを最小化します。
- 最小権限の原則（Principle of Least Privilege）の厳格な実装により、各ユーザー・サービスは業務遂行に必要な最小限のアクセス権限のみを付与されます。

**多層防御（Defense in Depth）戦略**
- ネットワーク層、アプリケーション層、データ層の複数レイヤーでセキュリティ制御を実装します。単一障害点を排除し、各層で独立したセキュリティ監視と制御を行うことで、一つの防御が突破されても他の層で脅威を検出・防御できる体制を構築します。
- 単一障害点の排除と冗長性の確保により、セキュリティ機能の可用性も保証します。

**セキュリティ・バイ・デザイン（Security by Design）**
- 設計段階からセキュリティを考慮し、脅威モデリングに基づくリスク評価を実施します。後付けのセキュリティ対策ではなく、アーキテクチャの根幹にセキュリティを組み込むことで、より堅牢で保守性の高いシステムを実現します。
- セキュリティ要件の明確化と実装により、開発・運用フェーズでの手戻りを最小化します。

#### コンプライアンス要件

**法的・規制要件への対応**
- **個人情報保護法**：顧客データの適切な取り扱いと保護を実現し、データ漏洩時の報告義務にも対応します。暗号化、アクセス制御、監査ログにより、法的要件を満たします。
- **GDPR**：EU域内データの処理において、データポータビリティや忘れられる権利などの厳格な規制に準拠します。データローカライゼーションとプライバシーバイデザインを実装します。
- **SOX法**：財務データの完全性と内部統制を確保し、監査証跡の長期保存を実現します。全ての財務関連操作は完全に追跡可能です。
- **ISO 27001**：情報セキュリティ管理システムの国際標準に準拠した運用体制を構築し、定期的な外部監査に対応します。

**業界標準への準拠**
- **NIST Cybersecurity Framework**：識別・防御・検知・対応・復旧の5つの機能でセキュリティ管理を標準化します。各機能について具体的な実装と測定指標を定義します。
- **CIS Controls**：優先順位付けされた20の重要セキュリティ制御を段階的に実装します。実装状況はSecurity Hubで継続的に監視します。
- **AWS Well-Architected Framework**：AWSのベストプラクティスに基づくセキュリティ設計を採用し、定期的なレビューで改善を継続します。

### 2. アカウントレベルセキュリティ（120アカウント対応）

#### アカウント分離とセキュリティ境界

**アカウント階層とセキュリティ境界設計**

**Root管理アカウント**
- **最小権限アクセス**：経営層3名のみがアクセス可能とし、日常運用では使用しません。これにより、最高権限の誤用や悪用を防ぎます。
- **強力な認証**：ハードウェアMFAを必須とし、物理的なセキュリティトークンで保護します。ソフトウェアMFAよりも高いセキュリティレベルを実現します。
- **監査証跡**：全アクションをCloudTrailで記録し、改ざん防止のため別アカウントに保存します。ログの完全性はログファイル検証機能で保証します。
- **アクセス制限**：本社IPアドレス（203.0.113.0/24）からのみアクセス可能とし、業務時間外（18:00-09:00）はアクセスを制限します。緊急時は承認プロセスを経て解除可能です。

**セキュリティ専用アカウント**
- **集中監視機能**：全120アカウントのセキュリティログを一元的に集約・分析します。Security Hubの委任管理者として機能し、組織全体のセキュリティ状況を可視化します。
- **独立性確保**：他アカウントからの影響を受けない独立運用により、セキュリティ機能の可用性を保証します。セキュリティアカウントへの変更は特別な承認プロセスが必要です。
- **権限分離**：セキュリティ管理者とシステム管理者の役割を明確に分離し、相互牽制を実現します。職務の分離（Separation of Duties）により内部不正を防止します。

**アカウント間セキュリティ通信**

セキュリティ通信フローは以下のように制御されます：

```
各アカウント → Security Account → 集中監視
├── CloudTrail ログ（S3直接書き込み、暗号化必須）
├── GuardDuty 検知情報（EventBridge経由）
├── Config 設定変更履歴（アグリゲーター）
├── Security Hub 統合レポート（委任管理者）
└── VPC Flow Logs（S3集中保存）
```

クロスアカウント通信制御：
- 最小権限によるAssumeRole設定で、必要な権限のみを付与
- 時間制限付きアクセス（業務時間のみ：09:00-18:00 JST）
- 特定IPからのアクセス制限（本社、データセンター、各拠点のIP）
- 全通信の監査ログ記録により、誰が、いつ、何をしたかを完全に追跡

#### アカウント別セキュリティ設定

**本番環境アカウント（24アカウント）**
- **厳格なアクセス制御**：本番環境への変更は承認制とし、Change Advisory Board（CAB）での事前レビューを必須とします。これにより、計画外の変更による障害を防止します。
- **データ暗号化**：保存時はKMS暗号化（AES-256）、転送時はTLS 1.2以上での完全暗号化を実装します。暗号化により、データ漏洩時も内容の保護を保証します。
- **監査ログ**：全操作を記録し、法的要件に基づき7年間の長期保存を実現します。ログはWORM（Write Once Read Many）ストレージに保存し、改ざんを防止します。
- **変更管理**：全変更の事前承認、影響評価、ロールバック計画の策定を義務付けます。変更失敗時の迅速な復旧を可能にします。

**開発・テスト環境アカウント（96アカウント）**
- **開発者権限**：必要最小限の権限を付与し、本番データへのアクセスは完全に遮断します。開発環境での事故が本番に影響しないよう隔離します。
- **データマスキング**：本番データを使用する場合は、個人情報を完全にマスキングします。これにより、開発環境でのデータ漏洩リスクを排除します。
- **アクセス時間制限**：業務時間外（22:00-06:00）のアクセスを制限し、異常な活動を検知します。深夜の不正アクセスを防止します。
- **定期的なリソース削除**：未使用リソースを自動削除（30日間未使用で削除）し、コスト最適化とセキュリティリスク低減を実現します。

### 3. Identity and Access Management（IAM）統合セキュリティ

#### IAM Identity Center統合認証

**フェデレーション認証基盤**

認証フローは以下のように実装されます：

```
Active Directory → IAM Identity Center → 120アカウント
├── SAML 2.0 認証（業界標準プロトコル）
├── グループベースの権限付与（AD グループと同期）
├── 条件付きアクセス（時間・場所・デバイス）
└── セッション管理（自動タイムアウト）
```

このフローにより、既存のAD認証基盤を活用しながら、AWSへの安全なアクセスを実現します。

#### Permission Set設計とセキュリティ制御

**管理者権限セット（厳格な制御）**

```json
{
  "OrganizationAdmin": {
    "AccessLevel": "Full",
    "MFA": "Required",
    "SessionDuration": "4時間",
    "IPRestriction": "本社IPのみ",
    "TimeRestriction": "業務時間のみ",
    "ApprovalRequired": "Yes"
  },
  "SecurityAdmin": {
    "AccessLevel": "SecurityServices",
    "MFA": "Required",
    "SessionDuration": "8時間",
    "IPRestriction": "セキュリティチームIPのみ",
    "AuditLogging": "Enhanced"
  }
}
```

管理者権限は厳格に制御され、不必要な特権の使用を防止します。

**開発者権限セット（環境別制御）**

```json
{
  "DeveloperFull": {
    "AccessLevel": "DevelopmentEnvironment",
    "MFA": "Required",
    "SessionDuration": "8時間",
    "ResourceLimits": "開発環境のみ",
    "CostControl": "月次予算制限"
  },
  "DeveloperRead": {
    "AccessLevel": "ReadOnly",
    "MFA": "Optional",
    "SessionDuration": "8時間",
    "ResourceScope": "開発環境のみ"
  }
}
```

開発者は必要な環境のみにアクセスでき、コスト制御も自動的に適用されます。

#### サービスロールセキュリティ設計

**ECS Task Role最小権限設計**

```json
{
  "20マイクロサービス別TaskRole": {
    "manufacturing-planning": {
      "DatabaseAccess": "aurora-prod-manufacturing-planning のみ",
      "S3Access": "専用バケットのみ",
      "SecretsManager": "専用シークレットのみ",
      "CloudWatchLogs": "専用ロググループのみ"
    },
    "sales-order": {
      "DatabaseAccess": "aurora-prod-sales-order のみ",
      "CrossServiceAPI": "inventory-check API のみ",
      "S3Access": "専用バケットのみ",
      "SecretsManager": "専用シークレットのみ"
    }
  }
}
```

各マイクロサービスは、業務遂行に必要な最小限のリソースのみにアクセス可能です。

**IAM Database認証セキュリティ**

```
Aurora IAM認証フロー：
ECS Task → IAM Role → Database Token (15分有効)
├── トークン自動ローテーション
├── 接続時間制限
├── 接続数制限
└── 全接続の監査ログ記録
```

データベースパスワードの管理が不要となり、セキュリティが向上します。

### 4. ネットワークセキュリティ（多層防御）

#### VPCセキュリティ設計

**ネットワーク分離とセキュリティ境界**

VPC分離戦略（120アカウント）：

```
管理系VPC (10.200.0.0/16)
├── Security Account VPC
├── Shared Services VPC
└── Network Hub VPC

事業部門VPC (10.0.0.0/8)
├── 製造部門 (10.0.0.0/14)
├── 販売部門 (10.1.0.0/14)  
├── サービス部門 (10.2.0.0/14)
└── IoT部門 (10.3.0.0/14)
```

この分離により、部門間の不正アクセスを防止し、影響範囲を限定します。

セキュリティ制御：
- プライベートサブネット中心の設計により、直接的なインターネット露出を最小化
- NATゲートウェイ経由の外部通信により、アウトバウンド通信を制御
- VPC Endpoint による AWS サービスアクセスで、インターネット経由の通信を排除
- Transit Gateway による制御された相互接続で、必要な通信のみを許可

**セキュリティグループ設計**

```json
{
  "セキュリティグループ階層": {
    "web-tier-sg": {
      "InboundRules": [
        {
          "Protocol": "HTTPS",
          "Port": 443,
          "Source": "ALB Security Group",
          "Description": "ALB からのHTTPS通信のみ"
        }
      ]
    },
    "app-tier-sg": {
      "InboundRules": [
        {
          "Protocol": "HTTP",
          "Port": 8080,
          "Source": "web-tier-sg",
          "Description": "Web層からのHTTP通信のみ"
        }
      ]
    },
    "db-tier-sg": {
      "InboundRules": [
        {
          "Protocol": "MySQL",
          "Port": 3306,
          "Source": "app-tier-sg",
          "Description": "App層からのMySQL通信のみ"
        }
      ]
    }
  }
}
```

階層間の通信を制限し、横方向の不正な移動を防止します。

#### Network Firewall実装

**ステートフルファイアウォール設定**

```yaml
# Network Firewall Rule Groups
StatefulRuleGroups:
  - Name: "malware-protection"
    Rules:
      - Action: "DROP"
        Header:
          Protocol: "TCP"
          Source: "ANY"
          Destination: "ANY"
        RuleOptions:
          - Keyword: "content"
            Values: ["malware-signature-patterns"]
            
  - Name: "intrusion-detection"
    Rules:
      - Action: "ALERT"
        Header:
          Protocol: "TCP"
          Source: "ANY"
          Destination: "ANY"
        RuleOptions:
          - Keyword: "sid"
            Values: ["1001"]
          - Keyword: "msg"
            Values: ["Suspicious network activity detected"]
```

既知のマルウェアパターンを検出・ブロックし、不審な活動をアラートします。

**ドメインフィルタリング設定**

```json
{
  "DomainFiltering": {
    "AllowedDomains": [
      "*.amazonaws.com",
      "*.technova.com",
      "github.com",
      "registry.npmjs.org"
    ],
    "BlockedCategories": [
      "malware",
      "phishing",
      "gambling",
      "adult-content"
    ],
    "CustomBlockList": [
      "known-malicious-domains.txt",
      "cryptocurrency-mining-sites.txt"
    ]
  }
}
```

業務に必要なドメインのみを許可し、セキュリティリスクのあるサイトへのアクセスを防止します。

### 5. Web Application Firewall（WAF）統合保護

#### WAF設定とルール管理

**多層WAF配置**

```
WAF配置戦略：
CloudFront → WAF (Global)
├── DDoS Protection
├── Geo-blocking
├── Rate Limiting
└── Bot Management

ALB → WAF (Regional)
├── Application-specific Rules
├── Custom Rules
├── Managed Rule Groups
└── IP Reputation Lists

API Gateway → WAF (API Protection)
├── API-specific Rules
├── Request Validation
├── Rate Limiting per API Key
└── Payload Inspection
```

各層で異なる脅威に対応し、多層防御を実現します。

**WAFルール設定**

```json
{
  "WAFRuleGroups": {
    "AWSManagedRules": {
      "CommonRuleSet": {
        "Enabled": true,
        "Priority": 1,
        "OverrideAction": "None"
      },
      "KnownBadInputsRuleSet": {
        "Enabled": true,
        "Priority": 2,
        "OverrideAction": "None"
      },
      "SQLiRuleSet": {
        "Enabled": true,
        "Priority": 3,
        "OverrideAction": "None"
      },
      "XSSRuleSet": {
        "Enabled": true,
        "Priority": 4,
        "OverrideAction": "None"
      }
    },
    "CustomRules": {
      "RateLimitRule": {
        "Priority": 10,
        "Action": "Block",
        "Statement": {
          "RateBasedStatement": {
            "Limit": 1000,
            "AggregateKeyType": "IP"
          }
        }
      },
      "GeoBlockRule": {
        "Priority": 11,
        "Action": "Block",
        "Statement": {
          "GeoMatchStatement": {
            "CountryCodes": ["CN", "KP", "IR"]
          }
        }
      }
    }
  }
}
```

OWASP Top 10の脅威に対する防御と、地理的制限を実装します。

#### DDoS Protection統合

**AWS Shield Standard + Advanced設定**

```yaml
# Shield Protection Configuration
ShieldProtection:
  Resources:
    - CloudFront Distributions
    - Route 53 Hosted Zones
    - Application Load Balancers
    - Network Load Balancers
    - Elastic IP Addresses
    
  DDoSResponseTeam:
    - 24/7 Support Access
    - Incident Response Automation
    - Emergency Escalation Procedures
    
  AdvancedProtection:
    - Application Layer DDoS Protection
    - Attack Analytics and Reporting
    - Cost Protection Guarantee
```

L3/L4およびL7のDDoS攻撃から包括的に保護します。

### 6. 通信暗号化とTLS管理

#### エンドツーエンド暗号化戦略

**TLS暗号化基準**

```json
{
  "CommunicationEncryption": {
    "TLS暗号化基準": {
      "MinimumTLSVersion": "1.2",
      "PreferredTLSVersion": "1.3",
      "CipherSuites": [
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_128_GCM_SHA256"
      ],
      "CertificateAuthority": "AWS Certificate Manager",
      "CertificateValidation": "DNS validation",
      "AutomaticRenewal": "有効"
    },
    "通信フロー別暗号化": {
      "External_to_AWS": {
        "ClientToCloudFront": "TLS 1.3",
        "CloudFrontToOrigin": "TLS 1.2以上",
        "CustomHeaders": "暗号化必須"
      },
      "Internal_AWS_Services": {
        "ALBToECS": "TLS 1.2以上",
        "ECSToAurora": "TLS 1.2 + IAM認証",
        "ServiceToService": "mTLS (相互認証)",
        "VPCEndpoint": "TLS 1.2以上"
      },
      "Hybrid_OnPremises": {
        "DirectConnect": "MACsec暗号化",
        "VPN": "IPSec AES-256",
        "ApplicationLayer": "TLS 1.3"
      }
    }
  }
}
```

全ての通信経路で強力な暗号化を実装し、データの機密性を保護します。

#### マイクロサービス間通信暗号化

**Service-to-Service暗号化**

```yaml
# Microservice Communication Encryption
ServiceToServiceEncryption:
  ECS_Service_Connect:
    Encryption: "TLS 1.3"
    CertificateManagement: "AWS Certificate Manager"
    MutualTLS:
      ClientCertificate: "Service-specific certificates"
      ServerCertificate: "Service-specific certificates"
      CertificateRotation: "Automatic (90 days)"
      
  API_Gateway_Integration:
    UpstreamTLS: "TLS 1.2 minimum"
    DownstreamTLS: "TLS 1.3 preferred"
    CertificatePinning: "Enabled for critical services"
    
  Database_Connections:
    Aurora_MySQL:
      SSL_Mode: "REQUIRED"
      SSL_Cipher: "AES256-SHA256"
      CertificateVerification: "VERIFY_IDENTITY"
      
  Message_Queues:
    SQS: "Server-side encryption with KMS"
    SNS: "Message encryption in transit and at rest"
```

マイクロサービス間の通信も完全に暗号化し、内部ネットワークでの盗聴を防止します。

#### 証明書管理とローテーション

**AWS Certificate Manager統合**

```json
{
  "CertificateManagement": {
    "ドメイン別証明書戦略": {
      "PublicCertificates": {
        "*.technova.com": {
          "Type": "Wildcard SSL/TLS Certificate",
          "ValidationMethod": "DNS",
          "AutoRenewal": true,
          "UsedBy": ["CloudFront", "ALB", "API Gateway"]
        },
        "api.technova.com": {
          "Type": "Single Domain Certificate",
          "ValidationMethod": "DNS",
          "AutoRenewal": true,
          "UsedBy": ["API Gateway", "ECS Services"]
        }
      },
      "PrivateCertificates": {
        "internal.technova.local": {
          "Type": "Private CA Certificate",
          "IssuingCA": "AWS Private Certificate Authority",
          "UsedBy": ["Internal Service Communication"],
          "ValidityPeriod": "1 year"
        }
      }
    },
    "マイクロサービス別証明書": {
      "manufacturing-planning.internal": "Service-specific certificate",
      "sales-order.internal": "Service-specific certificate",
      "inventory-management.internal": "Service-specific certificate"
    }
  }
}
```

証明書の自動更新により、証明書期限切れによるサービス停止を防止します。

#### VPN・DirectConnect暗号化

**ハイブリッド接続暗号化**

```yaml
# Hybrid Connection Encryption
HybridEncryption:
  DirectConnect:
    MACsec:
      Enabled: true
      CipherSuite: "GCM-AES-256"
      KeyAgreement: "SAK (Secure Association Key)"
      ConnectivityAssociation: "Pre-shared key"
    VirtualInterface:
      BGP_MD5: "Enabled"
      BGP_Password: "Complex 32-character password"
      VLAN_Encryption: "802.1AE MACsec"
      
  Site_to_Site_VPN:
    IKE_Version: "IKEv2"
    Encryption_Algorithm: "AES-256"
    Integrity_Algorithm: "SHA-256"
    DH_Group: "Group 14 (2048-bit MODP)"
    PFS: "Perfect Forward Secrecy enabled"
    Tunnel_Configuration:
      Phase1_Lifetime: "28800 seconds"
      Phase2_Lifetime: "3600 seconds"
      Dead_Peer_Detection: "Enabled"
      
  Client_VPN:
    Protocol: "OpenVPN"
    Cipher: "AES-256-GCM"
    Auth: "SHA-256"
    Certificate_Authentication: "Mutual authentication"
```

オンプレミスとの接続も最高レベルの暗号化で保護します。

#### アプリケーション層暗号化

**データフロー暗号化**

```json
{
  "ApplicationLayerEncryption": {
    "API通信": {
      "REST_APIs": {
        "Protocol": "HTTPS only",
        "TLS_Version": "1.3",
        "HSTS": "Enabled",
        "Certificate_Transparency": "Enabled"
      },
      "GraphQL_APIs": {
        "Transport": "HTTPS/WSS",
        "Query_Encryption": "Field-level encryption for sensitive data",
        "Response_Encryption": "Conditional based on data classification"
      },
      "gRPC_Services": {
        "Transport": "HTTP/2 over TLS",
        "Application_Layer_Protocol_Negotiation": "Enabled",
        "Connection_Multiplexing": "Encrypted streams"
      }
    },
    "WebSocket通信": {
      "Protocol": "WSS (WebSocket Secure)",
      "TLS_Version": "1.3",
      "Message_Level_Encryption": "Additional AES-256 for sensitive payloads"
    },
    "ファイル転送": {
      "S3_Upload": "TLS 1.2 + Server-side encryption",
      "Direct_Upload": "Multipart upload with encryption",
      "Pre_signed_URLs": "Short expiration + HTTPS only"
    }
  }
}
```

アプリケーション層でも追加の暗号化を実装し、多層防御を実現します。

#### 暗号化監視・検証

**TLS監視とコンプライアンス**

```yaml
# TLS Monitoring and Compliance
TLSMonitoring:
  Certificate_Monitoring:
    - Expiration_Alerts: "30, 14, 7 days before expiration"
    - Certificate_Health_Checks: "Daily SSL Labs scans"
    - Weak_Cipher_Detection: "Automated scanning"
    - Mixed_Content_Detection: "HTTP resources on HTTPS pages"
    
  TLS_Configuration_Compliance:
    - Config_Rules:
        - "alb-tls-1-2-required"
        - "cloudfront-tls-1-2-required"
        - "api-gateway-tls-1-2-required"
    - Custom_Checks:
        - "Verify cipher suite compliance"
        - "Check certificate chain validity"
        - "Validate OCSP stapling"
        
  Traffic_Analysis:
    - Encrypted_Traffic_Percentage: "Target: 100%"
    - Unencrypted_Detection: "Immediate alerts"
    - TLS_Handshake_Failures: "Trending analysis"
    - Performance_Impact: "Latency monitoring"
```

暗号化の実装状況を継続的に監視し、セキュリティレベルを維持します。

#### 暗号化キー管理統合

**KMS統合暗号化**

```json
{
  "EncryptionKeyManagement": {
    "通信暗号化キー階層": {
      "TLS_Certificates": {
        "KeyType": "RSA-2048 or EC P-256",
        "Management": "AWS Certificate Manager",
        "Rotation": "Automatic"
      },
      "Application_Level_Keys": {
        "KeyType": "AES-256",
        "Management": "AWS KMS",
        "Usage": "Field-level encryption",
        "Rotation": "Annual"
      },
      "Service_Communication_Keys": {
        "KeyType": "EC P-256",
        "Management": "AWS Private CA",
        "Usage": "mTLS certificates",
        "Rotation": "Quarterly"
      }
    },
    "キーガバナンス": {
      "KeyAccess": "Role-based with least privilege",
      "KeyAuditing": "All key usage logged in CloudTrail",
      "KeyRotation": "Automated with business approval",
      "KeyRecovery": "Secure backup and recovery procedures"
    }
  }
}
```

暗号化キーのライフサイクル全体を適切に管理します。

#### 暗号化パフォーマンス最適化

**暗号化オーバーヘッド管理**

```yaml
# Encryption Performance Optimization
EncryptionPerformance:
  TLS_Optimization:
    - Session_Resumption: "TLS session tickets enabled"
    - OCSP_Stapling: "Enabled to reduce handshake latency"
    - Hardware_Acceleration: "AWS Nitro System utilization"
    - Connection_Reuse: "HTTP/2 connection multiplexing"
    
  Cipher_Suite_Optimization:
    - AEAD_Ciphers: "Preferred for authenticated encryption"
    - ECDHE_Key_Exchange: "Perfect Forward Secrecy"
    - Hardware_AES: "AES-NI instruction utilization"
    
  Load_Distribution:
    - SSL_Termination: "Load balancer level"
    - Connection_Pooling: "Backend SSL connection reuse"
    - Regional_Distribution: "Edge location SSL termination"
```

暗号化によるパフォーマンス影響を最小化し、ユーザー体験を維持します。

#### 暗号化コンプライアンス

**規制要件対応**

```json
{
  "EncryptionCompliance": {
    "FIPS_140_2": {
      "Level": "Level 2 validated modules",
      "Scope": "All cryptographic operations",
      "Implementation": "AWS FIPS endpoints"
    },
    "Common_Criteria": {
      "EAL_Level": "EAL4+",
      "Validated_Components": "AWS KMS, CloudHSM"
    },
    "Industry_Standards": {
      "PCI_DSS": "Strong cryptography for cardholder data",
      "GDPR": "Appropriate technical measures",
      "HIPAA": "Encryption of PHI in transit"
    },
    "国内規制": {
      "個人情報保護法": "個人データの安全管理措置",
      "サイバーセキュリティ基本法": "重要インフラの保護"
    }
  }
}
```

各種規制要件に準拠した暗号化を実装します。

### 7. コンテナセキュリティ（ECS/ECR）

#### ECRセキュリティ設定

**コンテナイメージセキュリティ**

```json
{
  "ECRSecurityConfiguration": {
    "ImageScanning": {
      "ScanOnPush": true,
      "ScanningFrequency": "CONTINUOUS",
      "VulnerabilityThreshold": {
        "Critical": "Block",
        "High": "Alert",
        "Medium": "Log",
        "Low": "Log"
      }
    },
    "ImageImmutability": true,
    "Encryption": {
      "Type": "KMS",
      "KMSKey": "service-specific-key"
    },
    "LifecyclePolicy": {
      "UntaggedImages": "Delete after 7 days",
      "TaggedImages": "Keep latest 10 versions"
    }
  }
}
```

コンテナイメージの脆弱性を継続的に監視し、セキュアな状態を維持します。

**脆弱性管理自動化**

```yaml
# Container Security Automation
VulnerabilityManagement:
  Detection:
    - Continuous Image Scanning
    - Runtime Vulnerability Assessment
    - Third-party Security Integration
    
  Response:
    - Automated Patch Deployment
    - Image Rebuild Triggers
    - Security Alert Notifications
    
  Compliance:
    - CIS Benchmark Compliance
    - NIST Container Security Guidelines
    - Industry Best Practices
```

脆弱性の検出から対応まで自動化し、迅速な対応を実現します。

#### ECS Runtimeセキュリティ

**コンテナランタイム保護**

```json
{
  "ECSSecurityConfiguration": {
    "TaskDefinitionSecurity": {
      "Privileged": false,
      "ReadOnlyRootFilesystem": true,
      "User": "non-root",
      "NetworkMode": "awsvpc",
      "RequireCompatibilities": ["FARGATE"]
    },
    "SecretsManagement": {
      "SecretProvider": "AWS Secrets Manager",
      "AutoRotation": true,
      "EncryptionInTransit": true
    },
    "LogConfiguration": {
      "LogDriver": "awslogs",
      "LogGroup": "/ecs/security-enhanced",
      "LogRetention": "30 days"
    }
  }
}
```

コンテナ実行時のセキュリティを最大化し、攻撃面を最小化します。

**Service Connect セキュリティ**

```yaml
# Service Connect Security Configuration
ServiceConnectSecurity:
  Encryption:
    - TLS 1.3 for Service Communication
    - Certificate Management via ACM
    - Automatic Certificate Rotation
    
  Authentication:
    - mTLS for Service-to-Service Communication
    - IAM Roles for Service Identity
    - Service Mesh Integration
    
  Monitoring:
    - Traffic Flow Analysis
    - Anomaly Detection
    - Security Event Correlation
```

サービス間通信のセキュリティを強化し、内部脅威から保護します。

### 8. データベースセキュリティ（Aurora）

#### Auroraセキュリティ設定

**データベース暗号化とアクセス制御**

```json
{
  "AuroraSecurityConfiguration": {
    "Encryption": {
      "EncryptionAtRest": {
        "Enabled": true,
        "KMSKey": "service-specific-key",
        "AlgorithmSuite": "AES-256"
      },
      "EncryptionInTransit": {
        "Enabled": true,
        "TLSVersion": "1.2",
        "CertificateValidation": true
      }
    },
    "AccessControl": {
      "IAMAuthentication": true,
      "DatabaseUserManagement": "IAM-based",
      "PasswordPolicy": {
        "Disabled": true,
        "Reason": "IAM authentication only"
      },
      "NetworkAccess": {
        "VPCOnly": true,
        "SecurityGroups": ["db-tier-sg"],
        "SubnetGroups": ["private-subnets-only"]
      }
    }
  }
}
```

データベースレベルでの多層防御により、データを保護します。

**データベース監査とモニタリング**

```yaml
# Database Security Monitoring
DatabaseAuditing:
  AuditLogging:
    - All Connection Attempts
    - Query Execution Logs
    - Schema Changes
    - Privilege Escalations
    
  PerformanceInsights:
    - Query Performance Monitoring
    - Resource Utilization Tracking
    - Anomaly Detection
    
  Alerting:
    - Suspicious Query Patterns
    - Unusual Connection Attempts
    - Performance Degradation
    - Security Policy Violations
```

データベースアクティビティを完全に監視し、不正アクセスを検出します。

#### データ分類と保護

**データ分類フレームワーク**

```json
{
  "DataClassification": {
    "Confidential": {
      "Examples": ["customer_personal_data", "financial_records"],
      "EncryptionRequired": true,
      "AccessRestrictions": "Need-to-know basis",
      "AuditLogging": "Enhanced",
      "DataRetention": "Legal requirements"
    },
    "Internal": {
      "Examples": ["business_processes", "internal_reports"],
      "EncryptionRequired": true,
      "AccessRestrictions": "Employee access only",
      "AuditLogging": "Standard",
      "DataRetention": "7 years"
    },
    "Public": {
      "Examples": ["product_specifications", "marketing_materials"],
      "EncryptionRequired": false,
      "AccessRestrictions": "Public access allowed",
      "AuditLogging": "Basic",
      "DataRetention": "As needed"
    }
  }
}
```

データの重要度に応じた適切な保護レベルを適用します。

### 9. S3セキュリティ・アクセス制御

#### S3バケットセキュリティ設計

**バケット分類とセキュリティレベル**

```json
{
  "S3SecurityArchitecture": {
    "バケット分類とセキュリティレベル": {
      "機密データバケット": {
        "Examples": [
          "technova-customer-data-prod",
          "technova-financial-records-prod",
          "technova-employee-data-prod"
        ],
        "SecurityLevel": "最高",
        "PublicAccessBlock": "全て有効",
        "BucketPolicy": "最小権限の原則",
        "Encryption": "Customer Managed KMS",
        "Versioning": "有効",
        "MFADelete": "必須",
        "AccessLogging": "完全",
        "EventNotifications": "全操作"
      },
      "アプリケーションデータバケット": {
        "Examples": [
          "technova-manufacturing-data-prod",
          "technova-sales-data-prod",
          "technova-service-data-prod",
          "technova-iot-data-prod"
        ],
        "SecurityLevel": "高",
        "PublicAccessBlock": "全て有効",
        "BucketPolicy": "サービス別制限",
        "Encryption": "SSE-S3",
        "Versioning": "有効",
        "AccessLogging": "標準",
        "LifecyclePolicy": "自動階層化"
      },
      "ログ・監査バケット": {
        "Examples": [
          "technova-cloudtrail-logs-prod",
          "technova-access-logs-prod",
          "technova-security-logs-prod"
        ],
        "SecurityLevel": "高",
        "PublicAccessBlock": "全て有効",
        "BucketPolicy": "読み取り専用（監査用）",
        "Encryption": "SSE-S3",
        "ObjectLock": "Governance Mode",
        "RetentionPeriod": "7年",
        "ImmutableAccess": "有効"
      }
    }
  }
}
```

バケットの用途に応じて適切なセキュリティレベルを適用し、過剰でも不足でもない保護を実現します。

#### IAMポリシーとバケットポリシーの組み合わせ

**階層的アクセス制御**

```json
{
  "S3AccessControl": {
    "サービス別IAMポリシー": {
      "manufacturing-service-s3-policy": {
        "Version": "2012-10-17",
        "Statement": [
          {
            "Effect": "Allow",
            "Action": [
              "s3:GetObject",
              "s3:PutObject",
              "s3:DeleteObject"
            ],
            "Resource": [
              "arn:aws:s3:::technova-manufacturing-data-prod/*",
              "arn:aws:s3:::technova-manufacturing-backup-prod/*"
            ],
            "Condition": {
              "StringEquals": {
                "s3:x-amz-server-side-encryption": "AES256"
              },
              "Bool": {
                "aws:SecureTransport": "true"
              }
            }
          },
          {
            "Effect": "Allow",
            "Action": [
              "s3:ListBucket"
            ],
            "Resource": [
              "arn:aws:s3:::technova-manufacturing-data-prod",
              "arn:aws:s3:::technova-manufacturing-backup-prod"
            ],
            "Condition": {
              "StringLike": {
                "s3:prefix": [
                  "production-orders/*",
                  "materials/*",
                  "workflows/*"
                ]
              }
            }
          }
        ]
      }
    }
  }
}
```

サービスごとに必要最小限のアクセス権限を付与し、横断的なアクセスを防止します。

**バケットポリシー例（機密データ用）**

```json
{
  "CustomerDataBucketPolicy": {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "DenyInsecureConnections",
        "Effect": "Deny",
        "Principal": "*",
        "Action": "s3:*",
        "Resource": [
          "arn:aws:s3:::technova-customer-data-prod",
          "arn:aws:s3:::technova-customer-data-prod/*"
        ],
        "Condition": {
          "Bool": {
            "aws:SecureTransport": "false"
          }
        }
      },
      {
        "Sid": "DenyUnEncryptedObjectUploads",
        "Effect": "Deny",
        "Principal": "*",
        "Action": "s3:PutObject",
        "Resource": "arn:aws:s3:::technova-customer-data-prod/*",
        "Condition": {
          "StringNotEquals": {
            "s3:x-amz-server-side-encryption": "aws:kms"
          }
        }
      },
      {
        "Sid": "AllowOnlySpecificKMSKey",
        "Effect": "Deny",
        "Principal": "*",
        "Action": "s3:PutObject",
        "Resource": "arn:aws:s3:::technova-customer-data-prod/*",
        "Condition": {
          "StringNotEquals": {
            "s3:x-amz-server-side-encryption-aws-kms-key-id": "arn:aws:kms:ap-northeast-1:123456789012:key/customer-data-key-id"
          }
        }
      },
      {
        "Sid": "AllowSpecificRolesOnly",
        "Effect": "Allow",
        "Principal": {
          "AWS": [
            "arn:aws:iam::123456789012:role/sales-customer-access-role",
            "arn:aws:iam::123456789012:role/service-customer-access-role"
          ]
        },
        "Action": [
          "s3:GetObject",
          "s3:PutObject"
        ],
        "Resource": "arn:aws:s3:::technova-customer-data-prod/*",
        "Condition": {
          "StringEquals": {
            "s3:x-amz-server-side-encryption": "aws:kms"
          },
          "DateGreaterThan": {
            "aws:CurrentTime": "2024-01-01T00:00:00Z"
          }
        }
      }
    ]
  }
}
```

複数の条件を組み合わせることで、多層的なアクセス制御を実現します。

#### S3 Access Pointsとマルチリージョンアクセス制御

**Access Points設計**

```yaml
# S3 Access Points Configuration
S3AccessPoints:
  manufacturing-data-ap:
    Bucket: "technova-manufacturing-data-prod"
    VPCConfiguration:
      VPCId: "vpc-manufacturing-prod"
    Policy:
      Version: "2012-10-17"
      Statement:
        - Effect: Allow
          Principal:
            AWS: "arn:aws:iam::123456789012:role/manufacturing-*"
          Action:
            - "s3:GetObject"
            - "s3:PutObject"
          Resource: "arn:aws:s3:ap-northeast-1:123456789012:accesspoint/manufacturing-data-ap/object/*"
          Condition:
            StringEquals:
              "s3:DataAccessPointAccount": "123456789012"
              
  sales-customer-data-ap:
    Bucket: "technova-customer-data-prod"
    VPCConfiguration:
      VPCId: "vpc-sales-prod"
    Policy:
      Version: "2012-10-17"
      Statement:
        - Effect: Allow
          Principal:
            AWS: "arn:aws:iam::123456789012:role/sales-customer-*"
          Action:
            - "s3:GetObject"
          Resource: "arn:aws:s3:ap-northeast-1:123456789012:accesspoint/sales-customer-data-ap/object/*"
          Condition:
            StringEquals:
              "s3:DataAccessPointAccount": "123456789012"
            IpAddress:
              "aws:SourceIp": ["10.1.0.0/16"]  # Sales VPC CIDR
```

Access Pointsにより、同一バケットに対して異なるアクセス制御を適用し、管理を簡素化します。

#### クロスリージョンレプリケーションセキュリティ

**レプリケーション設定とアクセス制御**

```json
{
  "CrossRegionReplication": {
    "ReplicationConfiguration": {
      "Role": "arn:aws:iam::123456789012:role/s3-replication-role",
      "Rules": [
        {
          "ID": "ReplicateCustomerDataToDR",
          "Status": "Enabled",
          "Priority": 1,
          "Filter": {
            "Prefix": "customer-data/"
          },
          "Destination": {
            "Bucket": "arn:aws:s3:::technova-customer-data-dr-osaka",
            "StorageClass": "STANDARD_IA",
            "EncryptionConfiguration": {
              "ReplicaKmsKeyID": "arn:aws:kms:ap-northeast-3:123456789012:key/dr-customer-data-key"
            },
            "AccessControlTranslation": {
              "Owner": "Destination"
            }
          }
        }
      ]
    },
    "ReplicationRolePolicy": {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Action": [
            "s3:GetObjectVersionForReplication",
            "s3:GetObjectVersionAcl"
          ],
          "Resource": "arn:aws:s3:::technova-customer-data-prod/*"
        },
        {
          "Effect": "Allow",
          "Action": [
            "s3:ReplicateObject",
            "s3:ReplicateDelete"
          ],
          "Resource": "arn:aws:s3:::technova-customer-data-dr-osaka/*"
        },
        {
          "Effect": "Allow",
          "Action": [
            "kms:Decrypt"
          ],
          "Resource": "arn:aws:kms:ap-northeast-1:123456789012:key/customer-data-key-id"
        },
        {
          "Effect": "Allow",
          "Action": [
            "kms:GenerateDataKey"
          ],
          "Resource": "arn:aws:kms:ap-northeast-3:123456789012:key/dr-customer-data-key"
        }
      ]
    }
  }
}
```

災害対策のレプリケーションでも、セキュリティレベルを維持します。

#### S3監査・ログ・アラート設定

**包括的S3監視**

```json
{
  "S3SecurityMonitoring": {
    "CloudTrailS3Events": {
      "DataEvents": [
        {
          "ReadWriteType": "All",
          "IncludeManagementEvents": true,
          "DataResources": [
            {
              "Type": "AWS::S3::Object",
              "Values": [
                "arn:aws:s3:::technova-customer-data-prod/*",
                "arn:aws:s3:::technova-financial-records-prod/*"
              ]
            }
          ]
        }
      ]
    },
    "S3AccessLogging": {
      "TargetBucket": "technova-s3-access-logs-prod",
      "TargetPrefix": "access-logs/",
      "LogObjectKeyFormat": "SimplePrefix"
    },
    "EventNotifications": {
      "CloudWatchEvents": [
        {
          "EventName": "ObjectCreated",
          "EventDestination": "SNS Topic",
          "FilterRules": [
            {
              "Name": "prefix",
              "Value": "sensitive-data/"
            }
          ]
        },
        {
          "EventName": "ObjectRemoved",
          "EventDestination": "Lambda Function",
          "Function": "s3-delete-alert-handler"
        }
      ]
    }
  }
}
```

S3アクティビティを完全に監視し、不正な操作を即座に検出します。

#### S3セキュリティ自動化

**自動修復・対応**

```yaml
# S3 Security Automation
S3SecurityAutomation:
  ComplianceMonitoring:
    - PolicyViolationDetection:
        Trigger: "Config Rule違反"
        Response: "自動アラート + 手動修復"
    - PublicAccessDetection:
        Trigger: "Public Read/Write検出"
        Response: "即座にブロック + セキュリティチーム通知"
    - UnencryptedObjectDetection:
        Trigger: "暗号化されていないオブジェクト検出"
        Response: "アップロードブロック + 自動暗号化"
        
  AccessAnomalyDetection:
    - UnusualAccessPatterns:
        Detection: "GuardDuty Malicious IP"
        Response: "IP自動ブロック + インシデント作成"
    - MassDownloadDetection:
        Detection: "大量ダウンロード (>1GB/hour)"
        Response: "一時的アクセス制限 + 調査開始"
    - CrossRegionAccessAnomaly:
        Detection: "通常と異なるリージョンからのアクセス"
        Response: "MFA再認証要求 + ログ強化"
        
  AutomatedRemediation:
    - S3-Bucket-Public-Access-Prohibited:
        RemediationAction: "aws-s3-bucket-public-access-block"
        Parameters:
          BlockPublicAcls: true
          BlockPublicPolicy: true
          IgnorePublicAcls: true
          RestrictPublicBuckets: true
    - S3-Bucket-SSL-Requests-Only:
        RemediationAction: "aws-s3-bucket-ssl-requests-only"
        Parameters:
          BucketPolicy: "DenyInsecureConnections"
```

セキュリティ違反を自動的に検出・修復し、人的ミスによるリスクを最小化します。

#### GDPR・データ保護法対応のS3設定

**個人データ保護特別設定**

```json
{
  "GDPRComplianceS3": {
    "PersonalDataBuckets": {
      "technova-customer-personal-data-prod": {
        "ObjectLockConfiguration": {
          "ObjectLockEnabled": "Enabled",
          "Rule": {
            "DefaultRetention": {
              "Mode": "GOVERNANCE",
              "Years": 7
            }
          }
        },
        "NotificationConfiguration": {
          "CloudWatchConfiguration": {
            "Events": ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"],
            "CloudWatchConfiguration": {
              "LogGroupName": "/aws/s3/gdpr-compliance"
            }
          }
        },
        "Tags": [
          {
            "Key": "DataClassification",
            "Value": "PersonalData"
          },
          {
            "Key": "GDPRScope",
            "Value": "true"
          },
          {
            "Key": "RetentionPeriod",
            "Value": "7years"
          }
        ]
      }
    },
    "DataSubjectRightsSupport": {
      "RightToErasure": {
        "AutomatedDeletion": "Lambda function triggered by API",
        "VerificationProcess": "Multi-step approval",
        "AuditTrail": "Complete deletion record in CloudTrail"
      },
      "RightToAccess": {
        "DataInventory": "S3 Inventory + Lambda processing",
        "ResponseTime": "30 days maximum",
        "DeliveryMethod": "Secure download link"
      }
    }
  }
}
```

GDPR要件に完全準拠し、データ主体の権利行使に対応します。

#### マイクロサービス別S3アクセスパターン

**20マイクロサービス用の個別S3アクセス制御**

```yaml
# Microservice-specific S3 Access Patterns
MicroserviceS3Access:
  Manufacturing:
    ProductionPlanningService:
      AllowedBuckets:
        - "technova-production-plans-prod"
        - "technova-manufacturing-reports-prod"
      AllowedActions: ["s3:GetObject", "s3:PutObject", "s3:ListBucket"]
      PathRestrictions: ["production-plans/*", "planning-reports/*"]
      
    InventoryManagementService:
      AllowedBuckets:
        - "technova-inventory-data-prod"
        - "technova-manufacturing-shared-prod"
      AllowedActions: ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
      CrossServiceAccess:
        - Service: "SalesOrderService"
          BucketPath: "technova-inventory-data-prod/stock-levels/*"
          Permission: "ReadOnly"
          
  Sales:
    CustomerManagementService:
      AllowedBuckets:
        - "technova-customer-data-prod"
      AllowedActions: ["s3:GetObject", "s3:PutObject"]
      DataClassification: "Confidential"
      EncryptionRequired: "Customer-managed KMS"
      AccessLogging: "Enhanced"
      
  IoT:
    TelemetryService:
      AllowedBuckets:
        - "technova-iot-telemetry-prod"
        - "technova-iot-processed-data-prod"
      AllowedActions: ["s3:PutObject", "s3:GetObject"]
      VolumeRestrictions:
        MaxObjectSize: "100MB"
        DailyUploadLimit: "10GB"
      LifecycleManagement:
        TransitionToIA: "30 days"
        TransitionToGlacier: "90 days"
```

各マイクロサービスに最適化されたS3アクセス制御により、セキュリティと利便性を両立します。

### 10. APIセキュリティ（Gateway/Cognito）

#### API Gatewayセキュリティ設定

**API認証と認可**

```json
{
  "APIGatewaySecurity": {
    "Authentication": {
      "CognitoUserPools": {
        "AuthType": "JWT",
        "TokenValidation": true,
        "ScopeValidation": true
      },
      "IAMRoles": {
        "ServiceToService": true,
        "CrossAccountAccess": "Restricted"
      }
    },
    "Authorization": {
      "ScopeBasedAccess": true,
      "ResourceBasedPolicies": true,
      "ContextualAccess": "IP, Time, Device"
    },
    "Throttling": {
      "BurstLimit": 1000,
      "RateLimit": 500,
      "QuotaLimit": "10000/day"
    }
  }
}
```

多層的な認証・認可により、APIの不正利用を防止します。

**API Gateway WAF統合**

```yaml
# API Gateway WAF Configuration
APIGatewayWAF:
  CustomRules:
    - Name: "API-specific-rate-limit"
      Priority: 1
      Action: "Block"
      Statement:
        RateBasedStatement:
          Limit: 100
          AggregateKeyType: "IP"
    - Name: "API-payload-validation"
      Priority: 2
      Action: "Block"
      Statement:
        SizeConstraintStatement:
          FieldToMatch:
            Body: {}
          ComparisonOperator: "GT"
          Size: 1048576  # 1MB limit
```

API固有の脅威に対する防御を実装します。

#### Cognitoセキュリティ強化

**ユーザープールセキュリティ設定**

```json
{
  "CognitoSecurity": {
    "PasswordPolicy": {
      "MinimumLength": 12,
      "RequireUppercase": true,
      "RequireLowercase": true,
      "RequireNumbers": true,
      "RequireSymbols": true,
      "TemporaryPasswordValidityDays": 1
    },
    "MFAConfiguration": {
      "MFARequired": true,
      "AllowedMFATypes": ["SMS", "TOTP"],
      "PreferredMFA": "TOTP"
    },
    "AccountSecurity": {
      "AccountRecovery": "Email and Phone",
      "PreventUserExistenceErrors": true,
      "AdvancedSecurityMode": "ENFORCED"
    },
    "DeviceTracking": {
      "ChallengeRequiredOnNewDevice": true,
      "DeviceOnlyRememberedOnUserPrompt": true
    }
  }
}
```

強固なパスワードポリシーとMFA必須化により、アカウント乗っ取りを防止します。

### 11. Secrets Managementと Key Management

#### AWS Secrets Manager統合

**シークレット管理戦略**

```json
{
  "SecretsManagement": {
    "SecretCategories": {
      "DatabaseCredentials": {
        "Scope": "Per-microservice",
        "RotationEnabled": true,
        "RotationInterval": "30 days",
        "EncryptionKey": "service-specific-kms-key"
      },
      "APIKeys": {
        "Scope": "Per-integration",
        "RotationEnabled": true,
        "RotationInterval": "90 days",
        "AccessLogging": "Enhanced"
      },
      "CertificateKeys": {
        "Scope": "Per-domain",
        "RotationEnabled": true,
        "RotationInterval": "365 days",
        "CertificateAuthority": "AWS ACM"
      }
    },
    "AccessControl": {
      "ResourceBasedPolicies": true,
      "IAMRoleBasedAccess": true,
      "VPCEndpointAccess": true,
      "CrossAccountAccess": "Restricted"
    }
  }
}
```

シークレットの自動ローテーションにより、長期間同じ認証情報を使用するリスクを排除します。

#### KMS Key Management

**暗号化キー階層**

```yaml
# KMS Key Management Strategy
KMSKeyHierarchy:
  CustomerMasterKeys:
    - Purpose: "Root Encryption"
      Type: "AWS Managed"
      Usage: "Organization Level"
    - Purpose: "Service Encryption"
      Type: "Customer Managed"
      Usage: "Per-microservice"
      KeyRotation: "Annual"
    - Purpose: "Data Encryption"
      Type: "Customer Managed"
      Usage: "Per-data-classification"
      KeyRotation: "Annual"
      
  KeyPolicies:
    - Principal: "Service Roles"
      Actions: ["kms:Decrypt", "kms:GenerateDataKey"]
      Conditions:
        - StringEquals:
            "kms:ViaService": "service-name.region.amazonaws.com"
```

階層的なキー管理により、適切なアクセス制御と監査性を実現します。

### 12. 監視・ログ・インシデント対応

#### 統合セキュリティ監視

**Security Hub統合**

```json
{
  "SecurityHubConfiguration": {
    "EnabledStandards": [
      "AWS Foundational Security Standard",
      "CIS AWS Foundations Benchmark",
      "PCI DSS Standard"
    ],
    "CustomInsights": [
      {
        "Name": "High-Severity-Findings",
        "Filters": {
          "SeverityLabel": ["HIGH", "CRITICAL"],
          "WorkflowStatus": ["NEW", "NOTIFIED"]
        }
      },
      {
        "Name": "Compliance-Failures",
        "Filters": {
          "ComplianceStatus": ["FAILED"],
          "RecordState": ["ACTIVE"]
        }
      }
    ],
    "Automation": {
      "AutomatedRemediationEnabled": true,
      "NotificationTargets": ["security-team-sns-topic"],
      "EscalationProcedures": "security-incident-response-playbook"
    }
  }
}
```

Security Hubにより、複数のセキュリティサービスからの検出事項を一元的に管理し、優先順位付けされた対応を実現します。

**CloudTrail統合監査**

```yaml
# CloudTrail Security Configuration
CloudTrailSecurity:
  OrganizationTrail:
    - MultiRegionTrail: true
    - IncludeGlobalServiceEvents: true
    - LogFileValidation: true
    - KMSEncryption: true
    - S3BucketPolicy: "Restrictive"
    
  DataEvents:
    - S3ObjectLevelLogging: true
    - LambdaFunctionLogging: true
    - DynamoDBTableLogging: true
    
  InsightSelectors:
    - ApiCallRateInsight: true
    - ApiErrorRateInsight: true
    
  LogAnalysis:
    - RealTimeProcessing: true
    - AnomalyDetection: true
    - ThreatIntelligence: true
```

全てのAPIコールを記録し、異常なアクティビティを早期に検出します。

#### インシデント対応フレームワーク

**自動インシデント対応**

```json
{
  "IncidentResponse": {
    "DetectionSources": [
      "GuardDuty",
      "Security Hub",
      "CloudWatch Alarms",
      "VPC Flow Logs",
      "WAF Logs"
    ],
    "ResponseAutomation": {
      "IsolationProcedures": {
        "NetworkIsolation": "Auto-quarantine suspicious instances",
        "AccessRevocation": "Disable compromised credentials",
        "TrafficBlocking": "WAF rule updates"
      },
      "NotificationProcedures": {
        "SecurityTeam": "Immediate alert via PagerDuty",
        "Management": "Executive summary within 1 hour",
        "Legal": "Data breach notification procedures"
      },
      "EvidenceCollection": {
        "MemoryDumps": "Automated collection",
        "LogPreservation": "Extended retention",
        "ForensicImages": "Automated snapshots"
      }
    }
  }
}
```

インシデント発生時の初動対応を自動化し、被害の拡大を防止します。

### 13. 災害復旧・事業継続のセキュリティ

#### DR環境セキュリティ

**大阪リージョンDRセキュリティ**

```yaml
# DR Security Configuration
DRSecurity:
  SecurityReplication:
    - SecurityGroups: "Synchronized"
    - NACLs: "Synchronized"
    - WAFRules: "Synchronized"
    - KMSKeys: "Cross-region replicated"
    
  AccessControl:
    - EmergencyAccess: "Break-glass procedures"
    - DRActivation: "Multi-person authorization"
    - SecurityValidation: "Pre-activation security checks"
    
  DataProtection:
    - EncryptionInTransit: "TLS 1.3"
    - EncryptionAtRest: "Customer managed KMS"
    - DataIntegrity: "Continuous validation"
    
  Monitoring:
    - SecurityEventReplication: "Real-time"
    - CrossRegionAlerting: "Enabled"
    - ComplianceValidation: "Automated"
```

DR環境でも本番環境と同等のセキュリティレベルを維持し、切り替え時のセキュリティギャップを防止します。

### 14. コンプライアンス・ガバナンス

#### 継続的コンプライアンス監視

**AWS Config統合**

```json
{
  "ConfigCompliance": {
    "ConfigRules": [
      {
        "RuleName": "encrypted-volumes",
        "Source": "AWS Config Managed Rule",
        "Scope": "All EBS volumes",
        "ComplianceType": "NON_COMPLIANT if not encrypted"
      },
      {
        "RuleName": "mfa-enabled-for-root",
        "Source": "AWS Config Managed Rule",
        "Scope": "Root account",
        "ComplianceType": "NON_COMPLIANT if MFA not enabled"
      },
      {
        "RuleName": "security-group-ssh-restricted",
        "Source": "AWS Config Managed Rule",
        "Scope": "All security groups",
        "ComplianceType": "NON_COMPLIANT if SSH open to 0.0.0.0/0"
      }
    ],
    "RemediationConfigurations": [
      {
        "ConfigRuleName": "encrypted-volumes",
        "TargetType": "SSM_DOCUMENT",
        "TargetId": "AWS-EncryptEBSVolume",
        "AutomationAssumeRole": "config-remediation-role"
      }
    ]
  }
}
```

設定のドリフトを継続的に監視し、コンプライアンス違反を自動的に修復します。

#### 定期的セキュリティ評価

**セキュリティ評価フレームワーク**

```yaml
# Security Assessment Framework
SecurityAssessment:
  VulnerabilityAssessment:
    - Frequency: "Monthly"
    - Scope: "All production systems"
    - Tools: ["AWS Inspector", "Third-party scanners"]
    - Reporting: "Executive dashboard"
    
  PenetrationTesting:
    - Frequency: "Quarterly"
    - Scope: "External-facing systems"
    - Authorization: "AWS penetration testing approval"
    - Reporting: "Detailed technical report"
    
  ComplianceAudit:
    - Frequency: "Annual"
    - Standards: ["ISO 27001", "SOC 2", "PCI DSS"]
    - Auditor: "Third-party certified"
    - Remediation: "Action plan with timelines"
    
  SecurityMetrics:
    - MeanTimeToDetection: "< 5 minutes"
    - MeanTimeToResponse: "< 30 minutes"
    - SecurityIncidents: "Trend analysis"
    - ComplianceScore: "99.5% target"
```

定期的な評価により、セキュリティ態勢の継続的な改善を実現します。

### 15. セキュリティ運用・管理

#### 実装対象サービス

**AWS Security Hub（セキュリティ統合管理）**
- 全120アカウントのセキュリティ状況を一元的に可視化し、優先順位付けされた対応を実現します。単一のダッシュボードで組織全体のセキュリティ態勢を把握できるため、効率的な管理が可能です。
- AWS標準に加え、業界標準（CIS、PCI DSS）への準拠状況を継続的に監視します。コンプライアンス違反は自動的に検出され、修復アクションが提案されます。

**Amazon GuardDuty（脅威検知）**
- 機械学習による異常検知で、既知・未知の脅威を早期発見します。VPCフローログ、DNSログ、CloudTrailイベントを分析し、不審なアクティビティを検出します。
- S3、EKS、EC2の各データソースを有効化し、包括的な監視を実現します。マルウェアスキャン機能により、実行中のワークロードからの脅威も検出可能です。

**AWS Config（コンプライアンス監視）**
- リソース設定の変更を追跡し、承認されていない変更を即座に検出します。設定履歴により、いつ、誰が、何を変更したかを完全に追跡できます。
- 自動修復アクションにより、設定のドリフトを防止します。例えば、暗号化が無効化されたEBSボリュームを自動的に再暗号化できます。

**Amazon CloudWatch（メトリクス・アラート）**
- セキュリティメトリクスの収集と可視化により、KPI管理を実現します。MTTD（平均検出時間）、MTTR（平均対応時間）などの重要指標を継続的に測定します。
- 異常値検出により、通常と異なるパターンを早期に発見します。機械学習ベースの異常検出により、閾値設定の手間を削減します。

#### Terraform実装コード例

```hcl
# Security Hub の組織レベル設定
resource "aws_securityhub_account" "main" {
  enable_default_standards = true
}

resource "aws_securityhub_standards_subscription" "aws_foundational" {
  standards_arn = "arn:aws:securityhub:::ruleset/finding-format/aws-foundational-security-standard"
  depends_on    = [aws_securityhub_account.main]
}

resource "aws_securityhub_standards_subscription" "cis" {
  standards_arn = "arn:aws:securityhub:::ruleset/finding-format/cis-aws-foundations-benchmark"
  depends_on    = [aws_securityhub_account.main]
}

# GuardDuty 設定（全機能有効化）
resource "aws_guardduty_detector" "main" {
  enable = true
  
  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }
  
  finding_publishing_frequency = "FIFTEEN_MINUTES"
  
  tags = {
    Name        = "Primary GuardDuty Detector"
    Environment = var.environment
  }
}

# セキュリティメトリクス用 CloudWatch カスタムメトリクス
resource "aws_cloudwatch_metric_alarm" "critical_security_findings" {
  alarm_name          = "critical-security-findings"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "Findings"
  namespace           = "AWS/SecurityHub"
  period              = "300"
  statistic           = "Sum"
  threshold           = "0"
  alarm_description   = "Critical security findings detected"
  
  dimensions = {
    ComplianceType = "FAILED"
    SeverityLabel  = "CRITICAL"
  }
  
  alarm_actions = [aws_sns_topic.security_alerts.arn]
  
  tags = {
    SecurityKPI = "CriticalFindings"
  }
}

# MTTR (Mean Time To Recovery) 計測用 Lambda
resource "aws_lambda_function" "security_metrics_collector" {
  filename      = "security_metrics.zip"
  function_name = "security-metrics-collector"
  role          = aws_iam_role.security_metrics_role.arn
  handler       = "index.handler"
  runtime       = "python3.9"
  timeout       = 300
  
  environment {
    variables = {
      CLOUDWATCH_NAMESPACE = "TechNova/Security"
      SECURITY_HUB_REGION  = var.aws_region
    }
  }
  
  tags = {
    Purpose = "Security KPI Collection"
  }
}

# セキュリティKPI計測用 EventBridge
resource "aws_cloudwatch_event_rule" "security_metrics_schedule" {
  name                = "security-metrics-collection"
  description         = "Collect security KPIs every 5 minutes"
  schedule_expression = "rate(5 minutes)"
}

resource "aws_cloudwatch_event_target" "security_metrics_target" {
  rule      = aws_cloudwatch_event_rule.security_metrics_schedule.name
  target_id = "SecurityMetricsLambda"
  arn       = aws_lambda_function.security_metrics_collector.arn
}
```

### 16. 新技術・脅威への対応

#### 実装対象サービス

**Amazon GuardDuty（脅威インテリジェンス）**
- カスタム脅威インテリジェンスフィードの統合により、業界固有の脅威に対応します。TechNova社の産業機械分野特有の脅威情報を取り込み、検知精度を向上させます。
- 既知の安全なIPリストにより、誤検知を削減します。本社、工場、取引先のIPアドレスをホワイトリストに登録し、業務影響を最小化します。

**AWS Lambda（脅威分析・自動対応）**
- 検知された脅威に対する自動対応ロジックを実装し、初動対応を高速化します。例えば、不審なEC2インスタンスの自動隔離、侵害されたIAMクレデンシャルの無効化を自動実行します。
- 脅威インテリジェンスの自動更新により、最新の脅威情報を活用します。MITRE ATT&CKフレームワークと連携し、攻撃手法を体系的に分析します。

**Amazon Comprehend（AI分析）**
- セキュリティイベントの自然言語処理により、高度な脅威分析を実現します。ログメッセージのパターン分析により、人間では見逃しがちな異常を検出します。
- 異常なパターンの検出精度を向上させます。過去のインシデントデータを学習し、類似パターンの早期発見を可能にします。

#### 脅威インテリジェンス統合

**外部フィードの活用**
- MITRE ATT&CKフレームワークとの統合により、攻撃手法の体系的な分析を実現します。検出された脅威を戦術・技術・手順（TTP）にマッピングし、攻撃の全体像を把握します。
- 業界固有の脅威情報共有により、同業他社の被害を未然に防ぎます。製造業向けのISACと連携し、最新の脅威情報を共有します。

**自動化された脅威ハンティング**
- 6時間ごとの自動脅威ハンティングにより、潜在的な脅威を早期発見します。通常の監視では検出されない高度な脅威を、プロアクティブに探索します。
- AIによる異常検知で、人間では見逃しがちなパターンを検出します。機械学習モデルにより、正常な動作パターンを学習し、微細な異常も検出可能です。

#### Terraform実装コード例

```hcl
# 脅威インテリジェンス用 S3 バケット
resource "aws_s3_bucket" "threat_intelligence" {
  bucket = "technova-threat-intel-${random_id.bucket_suffix.hex}"
  
  tags = {
    Purpose            = "Threat Intelligence Storage"
    DataClassification = "Confidential"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "threat_intel_encryption" {
  bucket = aws_s3_bucket.threat_intelligence.id
  
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.security_key.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

# GuardDuty カスタム脅威インテリジェンス
resource "aws_guardduty_threatintelset" "custom_iocs" {
  activate    = true
  detector_id = aws_guardduty_detector.main.id
  format      = "TXT"
  location    = "s3://${aws_s3_bucket.threat_intelligence.id}/iocs/malicious-ips.txt"
  name        = "CustomMaliciousIPs"
  
  tags = {
    Source = "Internal Threat Intelligence"
  }
}

resource "aws_guardduty_ipset" "known_safe_ips" {
  activate    = true
  detector_id = aws_guardduty_detector.main.id
  format      = "TXT"
  location    = "s3://${aws_s3_bucket.threat_intelligence.id}/allowlist/safe-ips.txt"
  name        = "KnownSafeIPs"
}

# 脅威インテリジェンス更新用 Lambda
resource "aws_lambda_function" "threat_intel_updater" {
  filename      = "threat_intel_updater.zip"
  function_name = "threat-intelligence-updater"
  role          = aws_iam_role.threat_intel_lambda_role.arn
  handler       = "index.handler"
  runtime       = "python3.9"
  timeout       = 900
  memory_size   = 512
  
  environment {
    variables = {
      THREAT_INTEL_BUCKET   = aws_s3_bucket.threat_intelligence.id
      GUARDDUTY_DETECTOR_ID = aws_guardduty_detector.main.id
      EXTERNAL_FEED_URLS    = "https://api.threatintel.com/v1/indicators"
      MITRE_ATTACK_API      = "https://attack.mitre.org/api/v2/"
    }
  }
  
  tags = {
    Purpose = "Threat Intelligence Automation"
  }
}

# AI異常検知用 Lambda（Amazon Comprehend使用）
resource "aws_lambda_function" "ai_anomaly_detector" {
  filename      = "ai_anomaly_detector.zip"
  function_name = "ai-anomaly-detector"
  role          = aws_iam_role.ai_detection_role.arn
  handler       = "index.handler"
  runtime       = "python3.9"
  timeout       = 300
  memory_size   = 1024
  
  environment {
    variables = {
      COMPREHEND_MODEL_ARN = aws_comprehend_document_classifier.security_classifier.arn
      ANOMALY_THRESHOLD    = "0.8"
      ALERT_SNS_TOPIC      = aws_sns_topic.ai_security_alerts.arn
    }
  }
}

# Amazon Comprehend セキュリティ分類モデル
resource "aws_comprehend_document_classifier" "security_classifier" {
  name                = "security-event-classifier"
  data_access_role_arn = aws_iam_role.comprehend_role.arn
  language_code       = "en"
  
  input_data_config {
    s3_uri = "s3://${aws_s3_bucket.ml_training_data.id}/security-training-data/"
  }
  
  tags = {
    Purpose   = "Security Event Classification"
    ModelType = "DocumentClassifier"
  }
}

# 脅威ハンティング用 EventBridge ルール
resource "aws_cloudwatch_event_rule" "threat_hunting_schedule" {
  name                = "automated-threat-hunting"
  description         = "Automated threat hunting every 6 hours"
  schedule_expression = "rate(6 hours)"
}

resource "aws_cloudwatch_event_target" "threat_hunting_target" {
  rule      = aws_cloudwatch_event_rule.threat_hunting_schedule.name
  target_id = "ThreatHuntingLambda"
  arn       = aws_lambda_function.threat_hunter.arn
}
```

### 17. セキュリティ教育・トレーニング

#### 実装対象サービス

**Amazon DynamoDB（教育記録・結果保存）**
- 従業員5,000名の教育履歴を体系的に管理し、コンプライアンス要件を満たします。受講履歴、テスト結果、認定状況を一元管理し、監査対応を容易にします。
- フィッシングシミュレーション結果を分析し、教育効果を定量化します。クリック率、報告率、対応時間などのメトリクスにより、セキュリティ意識の向上を測定します。

**Amazon SES（フィッシングシミュレーション）**
- 実際の攻撃を模したフィッシングメールで、従業員の警戒心を維持します。最新の攻撃手法を反映したシミュレーションにより、実践的な教育を実現します。
- クリック率、報告率などのメトリクスで、セキュリティ意識を測定します。部門別、役職別の分析により、リスクの高いグループを特定し、追加教育を実施します。

**AWS Lambda（教育システム制御）**
- 教育コンテンツの自動配信により、定期的な教育を確実に実施します。新入社員への自動教育割当、年次教育の自動リマインダーを実装します。
- 未受講者への自動リマインダーで、受講率100%を目指します。エスカレーション機能により、長期未受講者の上長へ通知します。

#### 教育プログラム設計

**階層別教育カリキュラム**
- **一般従業員**：年2回の基礎セキュリティ教育、四半期ごとのフィッシング訓練を実施します。パスワード管理、フィッシング識別、情報取扱いの基本を習得します。
- **開発者**：セキュアコーディング研修、脆弱性対応訓練を実施します。OWASP Top 10への対応、セキュリティテストの実施方法を学習します。
- **管理者**：インシデント対応訓練、セキュリティ監査対応を実施します。危機管理、コミュニケーション、意思決定プロセスを訓練します。

**効果測定と改善**
- フィッシングシミュレーションの成功率を95%以上に維持します。継続的な訓練により、高いセキュリティ意識を保持します。
- セキュリティインシデントの人的要因を前年比50%削減します。教育効果により、ヒューマンエラーによるインシデントを大幅に削減します。

#### Terraform実装コード例

```hcl
# 従業員セキュリティ教育記録用 DynamoDB
resource "aws_dynamodb_table" "security_training_records" {
  name         = "security-training-records"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "employee_id"
  range_key    = "training_date"
  
  attribute {
    name = "employee_id"
    type = "S"
  }
  
  attribute {
    name = "training_date"
    type = "S"
  }
  
  attribute {
    name = "training_type"
    type = "S"
  }
  
  global_secondary_index {
    name            = "TrainingTypeIndex"
    hash_key        = "training_type"
    range_key       = "training_date"
    projection_type = "ALL"
  }
  
  tags = {
    Purpose       = "Security Training Management"
    DataRetention = "7years"
  }
}

# フィッシングシミュレーション結果用 DynamoDB
resource "aws_dynamodb_table" "phishing_simulation_results" {
  name         = "phishing-simulation-results"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "employee_id"
  range_key    = "simulation_id"
  
  attribute {
    name = "employee_id"
    type = "S"
  }
  
  attribute {
    name = "simulation_id"
    type = "S"
  }
  
  attribute {
    name = "result_status"
    type = "S"
  }
  
  global_secondary_index {
    name            = "ResultStatusIndex"
    hash_key        = "result_status"
    range_key       = "simulation_id"
    projection_type = "ALL"
  }
  
  ttl {
    attribute_name = "expiry_time"
    enabled        = true
  }
  
  tags = {
    Purpose = "Phishing Simulation Analytics"
  }
}

# フィッシングシミュレーション用 SES 設定
resource "aws_ses_email_identity" "phishing_simulation" {
  email = "security-training@technova.com"
  
  tags = {
    Purpose = "Phishing Simulation"
  }
}

resource "aws_ses_configuration_set" "phishing_tracking" {
  name = "phishing-simulation-tracking"
  
  event_destination {
    name               = "cloudwatch-event-destination"
    enabled            = true
    matching_types     = ["send", "bounce", "complaint", "delivery", "open", "click"]
    
    cloudwatch_destination {
      default_value  = "0"
      dimension_name = "MessageTag"
      value_source   = "messageTag"
    }
  }
}

# フィッシングシミュレーション実行用 Lambda
resource "aws_lambda_function" "phishing_simulation" {
  filename      = "phishing_simulation.zip"
  function_name = "phishing-simulation-executor"
  role          = aws_iam_role.phishing_simulation_role.arn
  handler       = "index.handler"
  runtime       = "python3.9"
  timeout       = 300
  memory_size   = 512
  
  environment {
    variables = {
      SES_IDENTITY          = aws_ses_email_identity.phishing_simulation.email
      RESULTS_TABLE         = aws_dynamodb_table.phishing_simulation_results.name
      EMPLOYEE_DATABASE     = aws_dynamodb_table.employee_directory.name
      SIMULATION_TEMPLATES  = "s3://${aws_s3_bucket.training_content.id}/phishing-templates/"
      SUCCESS_THRESHOLD     = "95"
    }
  }
  
  tags = {
    Purpose = "Security Training Automation"
  }
}

# セキュリティ教育コンテンツ用 S3
resource "aws_s3_bucket" "training_content" {
  bucket = "technova-security-training-${random_id.bucket_suffix.hex}"
  
  tags = {
    Purpose = "Security Training Content"
  }
}

resource "aws_s3_bucket_policy" "training_content_policy" {
  bucket = aws_s3_bucket.training_content.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "RestrictToVPCEndpoint"
        Effect    = "Allow"
        Principal = "*"
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion"
        ]
        Resource = "${aws_s3_bucket.training_content.arn}/*"
        Condition = {
          StringEquals = {
            "aws:sourceVpce" = aws_vpc_endpoint.s3_endpoint.id
          }
        }
      }
    ]
  })
}

# 教育メトリクス用 CloudWatch ダッシュボード
resource "aws_cloudwatch_dashboard" "security_training_dashboard" {
  dashboard_name = "security-training-metrics"
  
  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        
        properties = {
          metrics = [
            ["AWS/DynamoDB", "ConsumedReadCapacityUnits", "TableName", aws_dynamodb_table.security_training_records.name],
            ["AWS/DynamoDB", "ConsumedWriteCapacityUnits", "TableName", aws_dynamodb_table.security_training_records.name],
            ["AWS/SES", "Send", "ConfigurationSet", aws_ses_configuration_set.phishing_tracking.name],
            ["AWS/SES", "Open", "ConfigurationSet", aws_ses_configuration_set.phishing_tracking.name]
          ]
          period = 300
          stat   = "Sum"
          region = var.aws_region
          title  = "Security Training Activity"
        }
      },
      {
        type   = "log"
        x      = 0
        y      = 6
        width  = 12
        height = 6
        
        properties = {
          query  = "SOURCE '/aws/lambda/phishing-simulation-executor' | fields @timestamp, @message | filter @message like /SUCCESS/ | stats count() by bin(5m)"
          region = var.aws_region
          title  = "Phishing Simulation Success Rate"
        }
      }
    ]
  })
}
```

### 18. サプライチェーンセキュリティ

#### 実装対象サービス

**AWS Systems Manager（ベンダー評価管理）**
- サプライヤーのセキュリティ評価結果を一元管理し、リスクの可視化を実現します。評価基準の標準化により、客観的なベンダー選定が可能になります。
- 定期的な再評価により、継続的なリスク管理を実施します。年次評価の自動化により、評価漏れを防止します。

**Amazon Inspector（コンテナ・依存関係スキャン）**
- コンテナイメージの脆弱性を継続的にスキャンし、既知の脆弱性を排除します。CVEデータベースと連携し、最新の脆弱性情報に基づく検査を実施します。
- 依存関係の脆弱性も含めて包括的に検査し、サプライチェーン攻撃を防ぎます。オープンソースライブラリの脆弱性も検出し、早期対応を可能にします。

**AWS CodeBuild（セキュアビルドパイプライン）**
- ビルド環境を隔離し、ビルドプロセスへの不正な介入を防ぎます。各ビルドは独立した環境で実行され、クロスコンタミネーションを防止します。
- SBOM（Software Bill of Materials）を自動生成し、使用コンポーネントを追跡します。全ての依存関係を記録し、脆弱性発覚時の影響範囲を即座に特定できます。

**Amazon ECR（コンテナイメージセキュリティ）**
- イメージの不変性により、承認済みイメージのみが使用されることを保証します。タグの上書きを防止し、デプロイメントの一貫性を維持します。
- 脆弱性レベルに応じた自動対応で、高リスクイメージの使用を防止します。Criticalレベルの脆弱性を持つイメージは自動的にブロックされます。

#### ベンダーリスク管理

**ベンダー評価プロセス**
- 新規ベンダーのセキュリティ評価を必須化し、リスクレベルを3段階で分類します。高リスクベンダーには追加の管理策を適用します。
- 年次での再評価により、継続的なリスク管理を実現します。セキュリティインシデント発生時は臨時評価を実施します。

**依存関係の可視化**
- 全てのオープンソースコンポーネントをSBOMで管理します。ライセンス、バージョン、既知の脆弱性を追跡します。
- ライセンスリスク、セキュリティリスクを継続的に評価します。GPL汚染リスクや、脆弱性の多いコンポーネントを早期に特定します。

#### Terraform実装コード例

```hcl
# Inspector V2 有効化（コンテナ・EC2脆弱性スキャン）
resource "aws_inspector2_enabler" "organization" {
  account_ids    = [data.aws_caller_identity.current.account_id]
  resource_types = ["ECR", "EC2"]
}

# ECR レポジトリセキュリティ設定
resource "aws_ecr_repository" "secure_apps" {
  count                = length(var.application_names)
  name                 = var.application_names[count.index]
  image_tag_mutability = "IMMUTABLE"
  
  image_scanning_configuration {
    scan_on_push = true
  }
  
  encryption_configuration {
    encryption_type = "KMS"
    kms_key        = aws_kms_key.ecr_key.arn
  }
  
  tags = {
    Purpose          = "Secure Container Registry"
    SecurityScanning = "Enabled"
  }
}

# ECR ライフサイクルポリシー（古い脆弱性のあるイメージ削除）
resource "aws_ecr_lifecycle_policy" "security_policy" {
  count      = length(aws_ecr_repository.secure_apps)
  repository = aws_ecr_repository.secure_apps[count.index].name
  
  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Delete images with HIGH or CRITICAL vulnerabilities older than 7 days"
        selection = {
          tagStatus      = "any"
          countType      = "sinceImagePushed"
          countUnit      = "days"
          countNumber    = 7
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}

# CodeBuild セキュアビルドプロジェクト
resource "aws_codebuild_project" "secure_build" {
  name         = "secure-build-pipeline"
  description  = "Secure build pipeline with security scanning"
  service_role = aws_iam_role.codebuild_role.arn
  
  artifacts {
    type = "CODEPIPELINE"
  }
  
  environment {
    compute_type                = "BUILD_GENERAL1_MEDIUM"
    image                      = "aws/codebuild/amazonlinux2-x86_64-standard:3.0"
    type                       = "LINUX_CONTAINER"
    image_pull_credentials_type = "CODEBUILD"
    privileged_mode            = true
    
    environment_variable {
      name  = "SNYK_TOKEN"
      value = aws_ssm_parameter.snyk_token.name
      type  = "PARAMETER_STORE"
    }
    
    environment_variable {
      name  = "SECURITY_SCAN_THRESHOLD"
      value = "HIGH"
    }
  }
  
  source {
    type      = "CODEPIPELINE"
    buildspec = "buildspec-security.yml"
  }
  
  tags = {
    Purpose = "Secure Software Supply Chain"
  }
}

# ベンダー評価結果保存用 DynamoDB
resource "aws_dynamodb_table" "vendor_assessments" {
  name         = "vendor-security-assessments"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "vendor_id"
  range_key    = "assessment_date"
  
  attribute {
    name = "vendor_id"
    type = "S"
  }
  
  attribute {
    name = "assessment_date"
    type = "S"
  }
  
  attribute {
    name = "risk_level"
    type = "S"
  }
  
  global_secondary_index {
    name            = "RiskLevelIndex"
    hash_key        = "risk_level"
    range_key       = "assessment_date"
    projection_type = "ALL"
  }
  
  tags = {
    Purpose       = "Vendor Risk Management"
    DataRetention = "7years"
  }
}

# 依存関係チェック用 Lambda
resource "aws_lambda_function" "dependency_checker" {
  filename      = "dependency_checker.zip"
  function_name = "dependency-security-checker"
  role          = aws_iam_role.dependency_checker_role.arn
  handler       = "index.handler"
  runtime       = "python3.9"
  timeout       = 900
  memory_size   = 1024
  
  environment {
    variables = {
      VULNERABILITY_DATABASE = "https://api.osv.dev/v1/query"
      SNYK_API_URL          = "https://api.snyk.io/v1/"
      RESULTS_TABLE         = aws_dynamodb_table.dependency_scan_results.name
      SEVERITY_THRESHOLD    = "HIGH"
    }
  }
  
  tags = {
    Purpose = "Software Supply Chain Security"
  }
}

# SBOM (Software Bill of Materials) 保存用 S3
resource "aws_s3_bucket" "sbom_storage" {
  bucket = "technova-sbom-${random_id.bucket_suffix.hex}"
  
  tags = {
    Purpose            = "SBOM Storage"
    DataClassification = "Internal"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "sbom_lifecycle" {
  bucket = aws_s3_bucket.sbom_storage.id
  
  rule {
    id     = "sbom_retention"
    status = "Enabled"
    
    expiration {
      days = 2555  # 7 years retention
    }
    
    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
}
```

### 19. プライバシー・データ保護

#### 実装対象サービス

**Amazon Macie（個人情報自動検出）**
- S3バケット内の個人情報を自動検出し、意図しない露出を防ぎます。機械学習により、構造化・非構造化データから個人情報を高精度で検出します。
- データ分類の自動化により、適切な保護レベルを適用します。検出されたデータの種類に応じて、自動的にタグ付けとアクセス制御を適用します。

**AWS KMS（暗号化キー管理）**
- データ分類に応じた暗号化キーの使い分けで、アクセス制御を強化します。機密データ、内部データ、公開データそれぞれに専用のKMSキーを使用します。
- 自動キーローテーションにより、長期的な暗号化の安全性を保証します。年次でのキーローテーションを自動化し、古いキーの無効化も管理します。

#### GDPR・個人情報保護法対応

**データ主体の権利対応**
- **アクセス権**：30日以内に個人データの開示が可能な体制を構築します。自動化されたデータ収集により、分散したデータも漏れなく抽出できます。
- **削除権（忘れられる権利）**：承認プロセスを経て、全システムから確実に削除します。削除の完全性を保証し、バックアップからも削除します。
- **データポータビリティ権**：構造化された形式でのデータエクスポート機能を提供します。機械可読形式（JSON、CSV）でのエクスポートが可能です。

**データローカライゼーション**
- 日本の個人データは東京リージョンのみに保存し、海外転送を制限します。S3バケットポリシーとIAMポリシーの組み合わせで、リージョン外へのコピーを防止します。
- EUデータは専用バケットで管理し、GDPR要件を完全に満たします。データレジデンシー要件に準拠し、EU域外への転送は標準契約条項（SCC）に基づきます。

#### Terraform実装コード例

```hcl
# Amazon Macie 有効化（個人情報検出）
resource "aws_macie2_account" "main" {
  finding_publishing_frequency = "FIFTEEN_MINUTES"
  status                      = "ENABLED"
}

# Macie カスタム分類ジョブ
resource "aws_macie2_classification_job" "pii_discovery" {
  job_type = "SCHEDULED"
  name     = "pii-discovery-job"
  
  s3_job_definition {
    bucket_definitions {
      account_id = data.aws_caller_identity.current.account_id
      buckets    = [aws_s3_bucket.data_lake.arn]
    }
    
    scoping {
      excludes {
        and {
          simple_scope_term {
            comparator = "STARTS_WITH"
            key        = "OBJECT_KEY"
            values     = ["logs/", "temp/"]
          }
        }
      }
    }
  }
  
  schedule_frequency = "DAILY"
  
  tags = {
    Purpose = "PII Discovery and Classification"
  }
}

# 地域別データ分離用 S3 バケット（日本）
resource "aws_s3_bucket" "japan_data" {
  bucket = "technova-japan-data-${random_id.bucket_suffix.hex}"
  
  tags = {
    DataResidency = "Japan"
    GDPRScope     = "false"
    Purpose       = "Japan Personal Data Storage"
  }
}

resource "aws_s3_bucket_policy" "japan_data_policy" {
  bucket = aws_s3_bucket.japan_data.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "RestrictToJapanOnly"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.japan_data.arn,
          "${aws_s3_bucket.japan_data.arn}/*"
        ]
        Condition = {
          StringNotEquals = {
            "aws:RequestedRegion" = "ap-northeast-1"
          }
        }
      }
    ]
  })
}

# EU データ用 S3 バケット（GDPR対応）
resource "aws_s3_bucket" "eu_data" {
  bucket = "technova-eu-data-${random_id.bucket_suffix.hex}"
  
  tags = {
    DataResidency = "EU"
    GDPRScope     = "true"
    Purpose       = "EU Personal Data Storage"
  }
}

# GDPR データ主体権利対応用 Lambda
resource "aws_lambda_function" "gdpr_rights_handler" {
  filename      = "gdpr_rights_handler.zip"
  function_name = "gdpr-data-subject-rights"
  role          = aws_iam_role.gdpr_lambda_role.arn
  handler       = "index.handler"
  runtime       = "python3.9"
  timeout       = 900
  memory_size   = 1024
  
  environment {
    variables = {
      EU_DATA_BUCKET       = aws_s3_bucket.eu_data.id
      JAPAN_DATA_BUCKET    = aws_s3_bucket.japan_data.id
      MACIE_FINDINGS_TABLE = aws_dynamodb_table.macie_findings.name
      DATA_CATALOG_TABLE   = aws_dynamodb_table.data_catalog.name
      RESPONSE_DEADLINE    = "30"  # days
    }
  }
  
  tags = {
    Purpose = "GDPR Compliance Automation"
  }
}

# 個人データカタログ用 DynamoDB
resource "aws_dynamodb_table" "data_catalog" {
  name         = "personal-data-catalog"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "data_subject_id"
  range_key    = "data_location"
  
  attribute {
    name = "data_subject_id"
    type = "S"
  }
  
  attribute {
    name = "data_location"
    type = "S"
  }
  
  attribute {
    name = "data_type"
    type = "S"
  }
  
  attribute {
    name = "retention_date"
    type = "S"
  }
  
  global_secondary_index {
    name            = "DataTypeIndex"
    hash_key        = "data_type"
    range_key       = "retention_date"
    projection_type = "ALL"
  }
  
  ttl {
    attribute_name = "expiry_timestamp"
    enabled        = true
  }
  
  tags = {
    Purpose         = "Personal Data Inventory"
    GDPRCompliance = "Required"
  }
}

# 忘れられる権利対応用 Lambda
resource "aws_lambda_function" "right_to_erasure" {
  filename      = "right_to_erasure.zip"
  function_name = "gdpr-right-to-erasure"
  role          = aws_iam_role.erasure_lambda_role.arn
  handler       = "index.handler"
  runtime       = "python3.9"
  timeout       = 900
  
  environment {
    variables = {
      DATA_CATALOG_TABLE = aws_dynamodb_table.data_catalog.name
      BACKUP_BUCKET      = aws_s3_bucket.gdpr_backup.id
      LOG_GROUP          = aws_cloudwatch_log_group.gdpr_operations.name
    }
  }
  
  tags = {
    Purpose = "GDPR Right to Erasure"
  }
}

# データポータビリティ用 Lambda
resource "aws_lambda_function" "data_portability" {
  filename      = "data_portability.zip"
  function_name = "gdpr-data-portability"
  role          = aws_iam_role.portability_lambda_role.arn
  handler       = "index.handler"
  runtime       = "python3.9"
  timeout       = 900
  
  environment {
    variables = {
      DATA_CATALOG_TABLE = aws_dynamodb_table.data_catalog.name
      EXPORT_BUCKET      = aws_s3_bucket.data_export.id
      ENCRYPTION_KEY     = aws_kms_key.gdpr_key.arn
    }
  }
  
  tags = {
    Purpose = "GDPR Data Portability"
  }
}

# GDPR 監査ログ用 CloudWatch Log Group
resource "aws_cloudwatch_log_group" "gdpr_operations" {
  name              = "/aws/gdpr/operations"
  retention_in_days = 2555  # 7 years
  kms_key_id        = aws_kms_key.gdpr_key.arn
  
  tags = {
    Purpose = "GDPR Operations Audit Log"
  }
}
```

### 20. セキュリティコスト最適化

#### 実装対象サービス

**AWS Cost Explorer（セキュリティコスト分析）**
- セキュリティサービスごとのコスト内訳を可視化し、ROIを測定します。GuardDuty、Security Hub、Macieなどのサービス別コストを追跡し、投資効果を定量化します。
- 未使用のセキュリティリソースを特定し、コスト削減機会を発見します。例えば、使用されていないWAFルールや、過剰なログ保存期間を特定します。

**AWS Budgets（セキュリティ予算管理）**
- セキュリティ予算の80%到達時と予測超過時にアラートを発報します。早期の警告により、予算超過を未然に防ぎます。
- 部門別、サービス別の予算管理により、コスト意識を醸成します。各部門のセキュリティコストを可視化し、責任を明確化します。

#### コスト最適化戦略

**使用率に基づく最適化**
- 70%以下の使用率のセキュリティサービスは、設定の見直しやダウングレードを検討します。例えば、過剰なGuardDutyのデータソースを無効化します。
- 重複するセキュリティ機能を統合し、全体コストを削減します。Security Hubで統合可能な機能は個別サービスを停止します。

**投資対効果の測定**
- セキュリティインシデントの削減によるコスト削減効果を定量化します。インシデント対応コストの削減額を算出し、セキュリティ投資を正当化します。
- コンプライアンス違反の回避による潜在的な損失回避額を算出します。罰金、訴訟費用、評判損失などの回避額を見積もります。

#### Terraform実装コード例

```hcl
# セキュリティコスト監視用 Cost Budget
resource "aws_budgets_budget" "security_services_budget" {
  name         = "security-services-budget"
  budget_type  = "COST"
  limit_amount = "10000"
  limit_unit   = "USD"
  time_unit    = "MONTHLY"
  
  cost_filters = {
    Service = [
      "Amazon GuardDuty",
      "AWS Security Hub",
      "Amazon Macie",
      "Amazon Inspector",
      "AWS Config",
      "AWS CloudTrail",
      "AWS Key Management Service"
    ]
  }
  
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                 = 80
    threshold_type            = "PERCENTAGE"
    notification_type         = "ACTUAL"
    subscriber_email_addresses = ["security-team@technova.com"]
  }
  
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                 = 100
    threshold_type            = "PERCENTAGE"
    notification_type         = "FORECASTED"
    subscriber_email_addresses = ["ciso@technova.com"]
  }
}

# セキュリティツール使用率分析用 Lambda
resource "aws_lambda_function" "security_cost_analyzer" {
  filename      = "security_cost_analyzer.zip"
  function_name = "security-cost-analyzer"
  role          = aws_iam_role.cost_analyzer_role.arn
  handler       = "index.handler"
  runtime       = "python3.9"
  timeout       = 600
  memory_size   = 512
  
  environment {
    variables = {
      COST_EXPLORER_REGION  = "us-east-1"
      SECURITY_SERVICES     = "GuardDuty,SecurityHub,Macie,Inspector,Config"
      UTILIZATION_THRESHOLD = "70"
      REPORT_BUCKET         = aws_s3_bucket.cost_reports.id
    }
  }
  
  tags = {
    Purpose = "Security Cost Optimization"
  }
}

# コスト最適化推奨事項保存用 DynamoDB
resource "aws_dynamodb_table" "cost_optimization_recommendations" {
  name         = "security-cost-optimization"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "service_name"
  range_key    = "recommendation_date"
  
  attribute {
    name = "service_name"
    type = "S"
  }
  
  attribute {
    name = "recommendation_date"
    type = "S"
  }
  
  attribute {
    name = "potential_savings"
    type = "N"
  }
  
  global_secondary_index {
    name            = "SavingsIndex"
    hash_key        = "potential_savings"
    range_key       = "recommendation_date"
    projection_type = "ALL"
  }
  
  tags = {
    Purpose = "Cost Optimization Tracking"
  }
}

# 未使用セキュリティリソース検出用 Lambda
resource "aws_lambda_function" "unused_security_resources" {
  filename      = "unused_resources_detector.zip"
  function_name = "unused-security-resources-detector"
  role          = aws_iam_role.resource_optimizer_role.arn
  handler       = "index.handler"
  runtime       = "python3.9"
  timeout       = 900
  memory_size   = 1024
  
  environment {
    variables = {
      UNUSED_THRESHOLD_DAYS = "30"
      AUTO_CLEANUP_ENABLED  = "false"
      NOTIFICATION_TOPIC    = aws_sns_topic.cost_optimization_alerts.arn
    }
  }
  
  tags = {
    Purpose = "Resource Optimization"
  }
}

# セキュリティツール ROI 分析用 CloudWatch ダッシュボード
resource "aws_cloudwatch_dashboard" "security_roi_dashboard" {
  dashboard_name = "security-investment-roi"
  
  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        
        properties = {
          metrics = [
            ["AWS/GuardDuty", "FindingCount", "DetectorId", aws_guardduty_detector.main.id],
            ["AWS/SecurityHub", "Findings", "ComplianceType", "FAILED"],
            ["AWS/Config", "NonCompliantRules"]
          ]
          period = 3600
          stat   = "Sum"
          region = var.aws_region
          title  = "Security Tools Effectiveness"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 12
        height = 6
        
        properties = {
          metrics = [
            ["AWS/Billing", "EstimatedCharges", "ServiceName", "Amazon GuardDuty"],
            ["AWS/Billing", "EstimatedCharges", "ServiceName", "AWS Security Hub"],
            ["AWS/Billing", "EstimatedCharges", "ServiceName", "Amazon Macie"]
          ]
          period = 86400
          stat   = "Maximum"
          region = "us-east-1"
          title  = "Security Services Cost Trend"
        }
      }
    ]
  })
}
```

### 21. 継続的改善・成熟度向上

#### 実装対象サービス

**AWS Well-Architected Tool（セキュリティ評価）**
- 四半期ごとにセキュリティピラーの評価を実施し、改善点を特定します。AWSのベストプラクティスに基づく客観的な評価により、改善の優先順位を決定します。
- 業界ベストプラクティスとのギャップ分析により、改善優先順位を決定します。同業他社との比較により、競争優位性を維持します。

**AWS Systems Manager（運用成熟度管理）**
- セキュリティ運用の標準化と自動化により、属人性を排除します。運用手順書をコード化し、誰でも同じ品質で運用できる体制を構築します。
- 運用手順書の一元管理により、インシデント対応の品質を向上させます。最新の手順書が常に利用可能な状態を維持します。

#### PDCAサイクルの実装

**継続的改善プロセス**
- **Plan**：四半期ごとのセキュリティ戦略レビューと計画策定を実施します。前四半期の振り返りと、新たな脅威への対応計画を立案します。
- **Do**：承認された改善施策の段階的な実装を行います。リスクを最小化しながら、着実に改善を進めます。
- **Check**：KPIによる効果測定と目標達成度の評価を実施します。定量的な指標により、改善効果を客観的に評価します。
- **Act**：評価結果に基づく戦略の修正と次期計画への反映を行います。学習した内容を次のサイクルに活かします。

**成熟度評価指標**
- セキュリティ成熟度モデル（NIST基準）でレベル4（管理された状態）を目指します。プロセスの標準化と測定により、予測可能な結果を実現します。
- 年次での第三者評価により、客観的な成熟度を測定します。外部専門家による評価で、内部評価のバイアスを排除します。

#### Terraform実装コード例

```hcl
# セキュリティ成熟度評価用 DynamoDB
resource "aws_dynamodb_table" "security_maturity_assessments" {
  name         = "security-maturity-assessments"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "assessment_id"
  range_key    = "assessment_date"
  
  attribute {
    name = "assessment_id"
    type = "S"
  }
  
  attribute {
    name = "assessment_date"
    type = "S"
  }
  
  attribute {
    name = "maturity_level"
    type = "N"
  }
  
  global_secondary_index {
    name            = "MaturityLevelIndex"
    hash_key        = "maturity_level"
    range_key       = "assessment_date"
    projection_type = "ALL"
  }
  
  tags = {
    Purpose = "Security Maturity Tracking"
  }
}

# セキュリティメトリクス集約用 Lambda
resource "aws_lambda_function" "security_metrics_aggregator" {
  filename      = "security_metrics_aggregator.zip"
  function_name = "security-metrics-aggregator"
  role          = aws_iam_role.metrics_aggregator_role.arn
  handler       = "index.handler"
  runtime       = "python3.9"
  timeout       = 900
  memory_size   = 1024
  
  environment {
    variables = {
      SECURITY_HUB_REGION   = var.aws_region
      GUARDDUTY_DETECTOR_ID = aws_guardduty_detector.main.id
      CONFIG_RECORDER_NAME  = aws_config_configuration_recorder.recorder.name
      MATURITY_TABLE        = aws_dynamodb_table.security_maturity_assessments.name
      CLOUDWATCH_NAMESPACE  = "TechNova/SecurityMaturity"
    }
  }
  
  tags = {
    Purpose = "Security Maturity Measurement"
  }
}

# セキュリティベンチマーク用 Systems Manager パラメータ
resource "aws_ssm_parameter" "security_benchmarks" {
  name = "/security/benchmarks/current"
  type = "String"
  
  value = jsonencode({
    detection_time_target        = 300     # 5 minutes
    containment_time_target      = 1800    # 30 minutes
    recovery_time_target         = 14400   # 4 hours
    false_positive_threshold     = 5       # 5%
    compliance_score_target      = 99.5    # 99.5%
    vulnerability_remediation = {
      critical = 2880   # 48 hours in minutes
      high     = 10080  # 7 days in minutes
    }
  })
  
  tags = {
    Purpose = "Security Performance Benchmarks"
  }
}

# PDCA サイクル実行用 Step Functions
resource "aws_sfn_state_machine" "security_pdca_cycle" {
  name     = "security-pdca-cycle"
  role_arn = aws_iam_role.step_functions_role.arn
  
  definition = jsonencode({
    Comment = "Security PDCA Cycle Automation"
    StartAt = "Plan"
    States = {
      Plan = {
        Type     = "Task"
        Resource = aws_lambda_function.security_planning.arn
        Next     = "Do"
        Retry = [{
          ErrorEquals     = ["Lambda.ServiceException", "Lambda.AWSLambdaException"]
          IntervalSeconds = 2
          MaxAttempts     = 3
          BackoffRate     = 2.0
        }]
      }
      Do = {
        Type     = "Task"
        Resource = aws_lambda_function.security_implementation.arn
        Next     = "Check"
        Retry = [{
          ErrorEquals     = ["Lambda.ServiceException", "Lambda.AWSLambdaException"]
          IntervalSeconds = 2
          MaxAttempts     = 3
          BackoffRate     = 2.0
        }]
      }
      Check = {
        Type     = "Task"
        Resource = aws_lambda_function.security_assessment.arn
        Next     = "Act"
        Retry = [{
          ErrorEquals     = ["Lambda.ServiceException", "Lambda.AWSLambdaException"]
          IntervalSeconds = 2
          MaxAttempts     = 3
          BackoffRate     = 2.0
        }]
      }
      Act = {
        Type     = "Task"
        Resource = aws_lambda_function.security_improvement.arn
        End      = true
        Retry = [{
          ErrorEquals     = ["Lambda.ServiceException", "Lambda.AWSLambdaException"]
          IntervalSeconds = 2
          MaxAttempts     = 3
          BackoffRate     = 2.0
        }]
      }
    }
  })
  
  tags = {
    Purpose = "Security Continuous Improvement"
  }
}

# セキュリティKPI可視化用 QuickSight データセット
resource "aws_quicksight_data_set" "security_kpis" {
  data_set_id = "security-kpis-dataset"
  name        = "Security KPIs Dataset"
  
  physical_table_map {
    physical_table_id = "security-metrics-table"
    
    s3_source {
      data_source_arn = aws_quicksight_data_source.security_metrics_s3.arn
      
      input_columns {
        name = "metric_name"
        type = "STRING"
      }
      
      input_columns {
        name = "metric_value"
        type = "DECIMAL"
      }
      
      input_columns {
        name = "timestamp"
        type = "DATETIME"
      }
      
      input_columns {
        name = "target_value"
        type = "DECIMAL"
      }
    }
  }
  
  tags = {
    Purpose = "Security KPI Visualization"
  }
}

# セキュリティ成熟度レポート生成用 EventBridge スケジュール
resource "aws_cloudwatch_event_rule" "monthly_maturity_assessment" {
  name                = "monthly-security-maturity-assessment"
  description         = "Monthly security maturity assessment"
  schedule_expression = "cron(0 9 1 * ? *)"  # 毎月1日 9:00 JST
}

resource "aws_cloudwatch_event_target" "maturity_assessment_target" {
  rule      = aws_cloudwatch_event_rule.monthly_maturity_assessment.name
  target_id = "MaturityAssessmentLambda"
  arn       = aws_lambda_function.security_metrics_aggregator.arn
}
```

### 22. セキュリティ実装ロードマップ

#### フェーズ1：基盤構築（月1-3）

**優先実装項目**
- **IAM Identity Center**：全ユーザーの統合認証基盤を構築し、ADとの連携を確立します。これにより、既存の認証情報を活用しながら、AWSへの安全なアクセスを実現します。
- **Security Hub**：組織全体のセキュリティ状況を可視化する基盤を構築します。全120アカウントからのセキュリティ情報を集約し、一元的な管理を開始します。
- **GuardDuty**：脅威検知サービスを全アカウントで有効化し、24時間365日の監視体制を確立します。既知・未知の脅威を早期に検出する体制を整えます。
- **CloudTrail**：全APIコールの記録を開始し、完全な監査証跡を確保します。セキュリティインシデント発生時の調査基盤を確立します。

**成功基準**
- 全アカウントでの基本セキュリティサービス有効化：100%達成
- MFA適用率：100%（全ユーザー必須）
- 基本的なセキュリティアラートの設定完了
- セキュリティチームによる24時間監視体制の確立

#### フェーズ2：強化実装（月4-6）

**優先実装項目**
- **Network Firewall**：ネットワーク層での脅威防御を実装し、既知のマルウェアや不正通信をブロックします。IDS/IPS機能により、高度な脅威も検出します。
- **WAF**：Webアプリケーション層の保護を実装し、OWASP Top 10の脅威から防御します。SQLインジェクション、XSSなどの攻撃を自動的にブロックします。
- **Macie**：個人情報の自動検出を開始し、データ保護体制を強化します。意図しない個人情報の露出を防止し、コンプライアンスリスクを低減します。
- **コンテナセキュリティ**：ECRでのイメージスキャン、ECSでのランタイム保護を実装します。脆弱性のあるコンテナの本番環境への展開を防止します。

**成功基準**
- 全本番環境での多層防御実装：100%完了
- 脆弱性スキャン自動化：全コンテナイメージ対象
- WAFによるブロック率：悪意のあるリクエストの95%以上
- 個人情報の検出と分類：全S3バケット対象

#### フェーズ3：高度化（月7-9）

**優先実装項目**
- **脅威インテリジェンス統合**：外部の脅威情報を取り込み、検知精度を向上させます。業界固有の脅威情報により、標的型攻撃への対応力を強化します。
- **自動対応**：検知された脅威への自動対応を実装し、初動対応を高速化します。人的対応の遅延による被害拡大を防止します。
- **AI活用**：機械学習による異常検知を導入し、未知の脅威も早期発見します。通常パターンを学習し、微細な異常も検出可能にします。

**成功基準**
- MTTD（平均検出時間）：5分以内達成
- 自動対応率：80%以上（Low/Medium severity）
- 誤検知率：5%以下
- AI による新規脅威検出：月間10件以上

#### フェーズ4：最適化（月10-12）

**優先実装項目**
- **コスト最適化**：セキュリティ投資の効率化を図り、ROIを最大化します。重複機能の統合、未使用リソースの削除により、コストを削減します。
- **成熟度向上**：セキュリティプロセスの標準化と自動化を完成させます。属人性を排除し、持続可能なセキュリティ運用体制を確立します。
- **継続的改善プロセス**：PDCAサイクルを確立し、常に最新の脅威に対応できる体制を構築します。定期的な評価と改善により、セキュリティレベルを維持・向上させます。

**成功基準**
- セキュリティROI：20%向上（コスト削減と効果向上の両立）
- 成熟度レベル：4（NIST基準）達成
- 自動化率：90%以上（定型的なセキュリティタスク）
- 改善提案実施率：80%以上（四半期ごと）

#### 実装管理体制

**プロジェクト体制**
- **エグゼクティブスポンサー**：CISO（最高情報セキュリティ責任者）
- **プロジェクトマネージャー**：セキュリティ部門長
- **技術リード**：クラウドセキュリティアーキテクト
- **実装チーム**：セキュリティエンジニア5名、クラウドエンジニア10名

**進捗管理**
- **週次レビュー**：実装進捗、課題、リスクの確認
- **月次ステアリングコミッティ**：経営層への報告と意思決定
- **フェーズゲートレビュー**：次フェーズへの移行判定
- **KPIダッシュボード**：リアルタイムでの進捗可視化

#### Terraform実装コード例

```hcl
# 実装フェーズ管理用 DynamoDB
resource "aws_dynamodb_table" "implementation_roadmap" {
  name         = "security-implementation-roadmap"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "phase_id"
  range_key    = "task_id"
  
  attribute {
    name = "phase_id"
    type = "S"
  }
  
  attribute {
    name = "task_id"
    type = "S"
  }
  
  attribute {
    name = "status"
    type = "S"
  }
  
  attribute {
    name = "priority"
    type = "S"
  }
  
  global_secondary_index {
    name            = "StatusIndex"
    hash_key        = "status"
    range_key       = "priority"
    projection_type = "ALL"
  }
  
  tags = {
    Purpose = "Implementation Progress Tracking"
  }
}

# フェーズ1実装用 CodePipeline
resource "aws_codepipeline" "phase1_foundation" {
  name     = "security-phase1-foundation"
  role_arn = aws_iam_role.codepipeline_role.arn
  
  artifact_store {
    location = aws_s3_bucket.pipeline_artifacts.bucket
    type     = "S3"
    
    encryption_key {
      id   = aws_kms_key.pipeline_key.arn
      type = "KMS"
    }
  }
  
  stage {
    name = "Source"
    
    action {
      name             = "Source"
      category         = "Source"
      owner            = "AWS"
      provider         = "S3"
      version          = "1"
      output_artifacts = ["source_output"]
      
      configuration = {
        S3Bucket    = aws_s3_bucket.terraform_source.bucket
        S3ObjectKey = "phase1-foundation.zip"
      }
    }
  }
  
  stage {
    name = "SecurityValidation"
    
    action {
      name             = "SecurityScan"
      category         = "Build"
      owner            = "AWS"
      provider         = "CodeBuild"
      version          = "1"
      input_artifacts  = ["source_output"]
      
      configuration = {
        ProjectName = aws_codebuild_project.security_validation.name
      }
    }
  }
  
  stage {
    name = "Deploy"
    
    action {
      name             = "DeployFoundation"
      category         = "Build"
      owner            = "AWS"
      provider         = "CodeBuild"
      version          = "1"
      input_artifacts  = ["source_output"]
      
      configuration = {
        ProjectName = aws_codebuild_project.phase1_deploy.name
      }
    }
  }
  
  tags = {
    Phase    = "Foundation"
    Priority = "Critical"
  }
}

# 実装進捗監視用 Lambda
resource "aws_lambda_function" "implementation_monitor" {
  filename      = "implementation_monitor.zip"
  function_name = "security-implementation-monitor"
  role          = aws_iam_role.implementation_monitor_role.arn
  handler       = "index.handler"
  runtime       = "python3.9"
  timeout       = 300
  
  environment {
    variables = {
      ROADMAP_TABLE         = aws_dynamodb_table.implementation_roadmap.name
      CODEPIPELINE_NAMES    = "security-phase1-foundation,security-phase2-enhancement"
      SLACK_WEBHOOK_URL     = aws_ssm_parameter.slack_webhook.name
      SUCCESS_CRITERIA_TABLE = aws_dynamodb_table.success_criteria.name
    }
  }
  
  tags = {
    Purpose = "Implementation Progress Monitoring"
  }
}

# 成功基準管理用 DynamoDB
resource "aws_dynamodb_table" "success_criteria" {
  name         = "implementation-success-criteria"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "phase_id"
  range_key    = "criterion_id"
  
  attribute {
    name = "phase_id"
    type = "S"
  }
  
  attribute {
    name = "criterion_id"
    type = "S"
  }
  
  attribute {
    name = "achievement_status"
    type = "S"
  }
  
  global_secondary_index {
    name            = "AchievementIndex"
    hash_key        = "achievement_status"
    range_key       = "phase_id"
    projection_type = "ALL"
  }
  
  tags = {
    Purpose = "Success Criteria Tracking"
  }
}

# フェーズゲート検証用 Lambda
resource "aws_lambda_function" "phase_gate_validator" {
  filename      = "phase_gate_validator.zip"
  function_name = "security-phase-gate-validator"
  role          = aws_iam_role.phase_gate_role.arn
  handler       = "index.handler"
  runtime       = "python3.9"
  timeout       = 600
  
  environment {
    variables = {
      SUCCESS_CRITERIA_TABLE = aws_dynamodb_table.success_criteria.name
      SECURITY_HUB_REGION    = var.aws_region
      COMPLIANCE_THRESHOLD   = "95"
      APPROVAL_SNS_TOPIC     = aws_sns_topic.phase_gate_approvals.arn
    }
  }
  
  tags = {
    Purpose = "Phase Gate Validation"
  }
}

# 実装進捗ダッシュボード
resource "aws_cloudwatch_dashboard" "implementation_progress" {
  dashboard_name = "security-implementation-progress"
  
  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        
        properties = {
          metrics = [
            ["AWS/CodePipeline", "PipelineExecutionSuccess", "PipelineName", aws_codepipeline.phase1_foundation.name],
            ["AWS/CodeBuild", "SucceededBuilds", "ProjectName", aws_codebuild_project.phase1_deploy.name]
          ]
          period = 3600
          stat   = "Sum"
          region = var.aws_region
          title  = "Implementation Pipeline Success Rate"
        }
      },
      {
        type   = "log"
        x      = 0
        y      = 6
        width  = 12
        height = 6
        
        properties = {
          query  = "SOURCE '/aws/lambda/security-implementation-monitor' | fields @timestamp, phase_id, completion_percentage | filter completion_percentage > 0 | stats max(completion_percentage) by phase_id"
          region = var.aws_region
          title  = "Phase Completion Progress"
        }
      }
    ]
  })
}

# 自動ロールバック機能用 Lambda
resource "aws_lambda_function" "implementation_rollback" {
  filename      = "implementation_rollback.zip"
  function_name = "security-implementation-rollback"
  role          = aws_iam_role.rollback_role.arn
  handler       = "index.handler"
  runtime       = "python3.9"
  timeout       = 900
  memory_size   = 1024
  
  environment {
    variables = {
      TERRAFORM_STATE_BUCKET = aws_s3_bucket.terraform_state.id
      BACKUP_RETENTION_DAYS  = "30"
      ROLLBACK_APPROVAL_TOPIC = aws_sns_topic.rollback_approvals.arn
    }
  }
  
  tags = {
    Purpose = "Implementation Rollback Automation"
  }
}

# 実装完了通知用 EventBridge ルール
resource "aws_cloudwatch_event_rule" "implementation_milestones" {
  name        = "security-implementation-milestones"
  description = "Security implementation milestone notifications"
  
  event_pattern = jsonencode({
    source      = ["custom.security.implementation"]
    detail-type = ["Phase Completion", "Milestone Achievement"]
    detail = {
      status = ["COMPLETED", "ACHIEVED"]
    }
  })
}

resource "aws_cloudwatch_event_target" "milestone_notification" {
  rule      = aws_cloudwatch_event_rule.implementation_milestones.name
  target_id = "MilestoneNotificationLambda"
  arn       = aws_lambda_function.milestone_notifier.arn
}
```

## まとめ

この包括的なセキュリティ設計により、TechNova社は120アカウントのマルチアカウント環境において、以下を実現します：

### 実現される価値

1. **ゼロトラストアーキテクチャ**による内部・外部脅威への包括的な対策
   - 全ての通信、アクセス、デバイスを検証し、「信頼せず、常に検証する」原則を実装
   - 最小権限の原則により、侵害時の影響範囲を最小化

2. **多層防御**による単一障害点の排除と段階的な脅威検出・防御
   - ネットワーク、アプリケーション、データの各層で独立した防御機構を実装
   - 一つの防御が突破されても、他の層で脅威を検出・阻止

3. **自動化**による人的ミスの削減と迅速な脅威対応
   - セキュリティタスクの90%以上を自動化し、運用負荷を大幅削減
   - 脅威検出から対応までの時間を従来の数時間から数分に短縮

4. **コンプライアンス**要件の完全な充足と継続的な監査対応
   - 個人情報保護法、GDPR、SOX法、ISO 27001などの要件を包括的にカバー
   - 自動化された監査証跡収集により、監査対応工数を80%削減

5. **コスト最適化**によるセキュリティ投資の効率化
   - 使用率に基づく最適化により、セキュリティコストを20%削減
   - ROI測定により、投資効果を定量的に証明

### 期待される成果

**定量的成果**
- セキュリティインシデント：前年比70%削減
- MTTD（平均検出時間）：30分→5分（83%改善）
- MTTR（平均対応時間）：4時間→30分（87.5%改善）
- コンプライアンススコア：85%→99.5%
- セキュリティ運用コスト：年間20%削減

**定性的成果**
- 経営層の安心感向上：リアルタイムでのセキュリティ状況可視化
- 開発者の生産性向上：セキュアな開発環境の自動提供
- 顧客信頼の向上：高度なセキュリティ対策による差別化
- 従業員のセキュリティ意識向上：継続的な教育とフィードバック

### 持続可能性

この設計は、現在の脅威環境に対応しながら、将来の技術進化や新たな脅威にも柔軟に対応できる、スケーラブルで持続可能なセキュリティ体制を提供します。継続的な改善プロセス（PDCA）により、常に最新のセキュリティレベルを維持し、TechNova社のビジネス成長を支えるセキュアな基盤となります。