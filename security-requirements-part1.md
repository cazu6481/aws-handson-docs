# セキュリティ要件 Part 1: セクション1-7（基本インフラセキュリティ）

## セキュリティ要件（完全統合版）

### TechNova社120アカウント構成における包括的セキュリティアーキテクチャ

## 1. 全体セキュリティ戦略とコンプライアンス要件

### セキュリティ設計原則

**Zero Trust アーキテクチャの採用**
- すべてのネットワークトラフィック、ユーザーアクセス、デバイス接続を検証します。従来の境界防御モデルから脱却し、「信頼せず、常に検証する」原則を徹底適用することで、内部脅威やラテラルムーブメントのリスクを最小化します。この設計により、VPN接続であっても、社内ネットワークからのアクセスであっても、すべての通信を同等に扱い、継続的な認証と認可を実施します。
- 「信頼せず、常に検証する」原則の徹底適用により、ネットワーク内部からの攻撃や、正規アカウントを悪用した攻撃にも対応可能な体制を構築します。具体的には、マイクロセグメンテーション、継続的な認証、コンテキストベースのアクセス制御を組み合わせることで、攻撃者の横展開を効果的に防止します。
- 最小権限の原則（Principle of Least Privilege）の厳格な実装により、各ユーザー・サービスは業務遂行に必要な最小限のアクセス権限のみを付与され、侵害時の影響範囲を限定します。権限の定期的な棚卸しと、使用されていない権限の自動削除により、権限のクリープ（徐々に権限が増加する現象）を防止します。

**多層防御（Defense in Depth）戦略**
- ネットワーク層、アプリケーション層、データ層の複数レイヤーでのセキュリティ制御を実装します。これにより、一つの防御層が突破されても、他の層で脅威を検出・阻止できる堅牢な防御体制を実現します。各層は独立して機能し、単一の脆弱性が全体のセキュリティを損なわないよう設計されています。
- 単一障害点の排除と冗長性の確保により、セキュリティ機能自体の可用性も保証し、攻撃者がセキュリティ機能を無効化しようとする試みにも対抗します。例えば、WAFが一時的に機能しなくても、ネットワークファイアウォールとアプリケーションレベルの検証により、攻撃を防御できます。
- 各層での独立したセキュリティ監視と制御により、異なる種類の脅威に対して最適化された防御メカニズムを適用できます。ネットワーク層ではDDoS攻撃、アプリケーション層ではSQLインジェクション、データ層では不正アクセスといった、層別に特化した対策を実装します。

**セキュリティ・バイ・デザイン（Security by Design）**
- 設計段階からのセキュリティ考慮により、後付けでは実現困難な根本的なセキュリティ対策を実装します。これにより、セキュリティホールの発生を未然に防ぎます。開発プロセスの初期段階でセキュリティ要件を定義し、アーキテクチャレビューを実施することで、構造的な脆弱性を排除します。
- 脅威モデリングに基づくリスク評価を実施し、想定される攻撃シナリオに対する対策を事前に組み込みます。STRIDE（Spoofing、Tampering、Repudiation、Information Disclosure、Denial of Service、Elevation of Privilege）モデルを使用し、体系的な脅威分析を行います。
- セキュリティ要件の明確化と実装により、開発・運用フェーズでの手戻りを最小化し、コスト効率の高いセキュリティ実装を実現します。セキュリティテストの自動化により、継続的インテグレーション/デリバリー（CI/CD）パイプラインに組み込み、品質を保証します。

### コンプライアンス要件

**法的・規制要件**

**個人情報保護法**
- 顧客データの適切な取り扱いと保護を実現します。暗号化、アクセス制御、監査ログの実装により、個人情報の漏洩を防止します。特に、個人情報の取得時の同意管理、利用目的の明確化、第三者提供の制限など、法的要件を技術的に実装します。
- データ漏洩時の72時間以内の報告義務に対応するため、自動検知と通知の仕組みを構築します。Amazon Macieによる個人情報の自動検出、GuardDutyによる異常アクセスの検知、自動化されたインシデント対応プロセスにより、迅速な報告を可能にします。

**GDPR（General Data Protection Regulation）**
- EU域内データの処理に関する厳格な規制対応を実施します。データポータビリティ、忘れられる権利、明示的な同意取得などの要件を技術的に実装します。Lambda関数による自動化されたデータ主体権利の行使対応により、30日以内の対応期限を確実に遵守します。
- データ保護影響評価（DPIA）の実施と、プライバシーバイデザインの原則に基づいた設計を行います。高リスクな処理を行う前に必ずDPIAを実施し、プライバシーリスクを事前に評価・軽減します。

**SOX法（Sarbanes-Oxley Act）**
- 財務データの完全性と内部統制を確保します。職務の分離、承認プロセス、監査証跡の完全性により、財務報告の信頼性を保証します。特に、財務システムへのアクセス制御、変更管理、監査ログの改ざん防止に重点を置きます。
- 四半期ごとの内部統制評価と、年次の外部監査に対応可能な体制を構築します。AWS Configによる継続的なコンプライアンス監視、CloudTrailによる完全な監査証跡により、監査人への証跡提供を効率化します。

**ISO 27001**
- 情報セキュリティ管理システムの国際標準準拠により、体系的なセキュリティ管理を実現します。リスクアセスメント、管理策の実装、有効性測定の継続的なサイクルを確立します。
- PDCAサイクルに基づく継続的改善プロセスを確立し、セキュリティレベルの維持・向上を図ります。Step Functionsによる自動化されたPDCAサイクルの実行により、改善活動の確実な実施を保証します。

**業界標準準拠**

**NIST Cybersecurity Framework**
- セキュリティ管理の標準化により、体系的で漏れのないセキュリティ対策を実現します。5つの機能（識別、防御、検知、対応、復旧）を包括的に実装し、サイバーレジリエンスを確保します。
- 識別（Identify）、防御（Protect）、検知（Detect）、対応（Respond）、復旧（Recover）の5つの機能を包括的に実装します。各機能に対応するAWSサービスを適切に選定し、統合的なセキュリティ体制を構築します。

**CIS Controls**
- 重要セキュリティ制御の実装により、実証済みの効果的な対策を適用します。特に、インベントリ管理、セキュア設定、継続的な脆弱性管理など、基本的かつ重要な制御に焦点を当てます。
- 優先順位付けされた20の制御により、限られたリソースで最大の効果を実現します。実装ガイドラインに従い、段階的に成熟度を向上させることで、実効性の高いセキュリティ対策を実現します。

**AWS Well-Architected Framework**
- クラウドセキュリティベストプラクティスの適用により、AWS環境に最適化されたセキュリティを実現します。セキュリティピラーの7つの設計原則に基づき、クラウドネイティブなセキュリティアーキテクチャを構築します。
- 定期的なWell-Architectedレビューにより、継続的な改善機会を特定します。四半期ごとのレビューセッションで、新しいサービスや機能を活用した改善提案を実施します。

## 2. アカウントレベルセキュリティ（120アカウント対応）

### アカウント分離とセキュリティ境界

**アカウント階層とセキュリティ境界設計**

**Root管理アカウント**
- **最小権限アクセス**：経営層3名のみアクセス可能とし、日常的な運用作業では一切使用しません。これにより、最高権限の悪用リスクを最小化します。Root権限の使用は、組織変更やアカウント作成など、年に数回程度の重要な作業に限定し、すべての使用を取締役会レベルで承認します。
- **強力な認証**：ハードウェアMFA必須により、フィッシングやマルウェアによる認証情報の窃取にも対抗できる強固な認証を実現します。YubiKeyなどのFIDO2準拠のハードウェアトークンを使用し、物理的な所持証明を要求することで、リモート攻撃を事実上不可能にします。
- **監査証跡**：全アクションの完全記録により、不正アクセスや誤操作の検出と原因究明を可能にします。ログは別アカウントに保存し、改ざんを防止します。CloudTrailログはS3 Object Lockで保護し、規制要件に応じて7年間の不変保存を実現します。
- **アクセス制限**：IP制限（本社IPのみ）、時間制限（業務時間のみ）の実装により、攻撃機会を大幅に削減します。さらに、アクセス時には事前申請と複数人による承認を必須とし、計画外のアクセスを完全に排除します。

**セキュリティ専用アカウント**
- **集中監視機能**：全120アカウントのセキュリティログ・監視の集中管理により、組織全体のセキュリティ状況を一元的に把握し、迅速な対応を可能にします。Security Hubのマスターアカウントとして機能し、すべてのセキュリティ検出事項を集約・優先順位付けします。
- **独立性確保**：他アカウントからの影響を受けない独立運用により、セキュリティ機能の可用性と完全性を保証します。このアカウントへのアクセスはセキュリティチームに限定し、開発者や運用チームからの干渉を防止します。
- **権限分離**：セキュリティ管理者とシステム管理者の役割分離により、内部不正や誤操作のリスクを低減します。職務の分離（Segregation of Duties）原則に基づき、単一の個人が監視の設定と無効化の両方を行えないよう制御します。

**アカウント間セキュリティ通信**

セキュリティ通信フロー：
```
各アカウント → Security Account → 集中監視
├── CloudTrail ログ（全APIコール記録）
├── GuardDuty 検知情報（脅威インテリジェンス）
├── Config 設定変更履歴（コンプライアンス監視）
├── Security Hub 統合レポート（優先順位付け）
└── VPC Flow Logs（ネットワーク通信記録）
```

このフローにより、分散環境でも一元的なセキュリティ監視を実現し、相関分析による高度な脅威検出を可能にします。

クロスアカウント通信制御：
- 最小権限によるAssumeRole設定により、必要最小限の権限のみを付与し、権限昇格攻撃を防止します。各ロールは特定のアクションに限定され、時間制限付きの一時的な認証情報を使用します。
- 時間制限付きアクセス（業務時間のみ）により、攻撃可能な時間帯を限定します。夜間や週末のアクセスは原則禁止とし、緊急時のみ承認プロセスを経て許可します。
- 特定IPからのアクセス制限により、外部からの不正アクセスを防止します。オフィスIPアドレスとVPNゲートウェイのみを許可し、それ以外からのアクセスを技術的に不可能にします。
- 全通信の監査ログ記録により、異常なアクセスパターンを検出可能にします。機械学習を活用した異常検知により、通常とは異なるアクセスパターンを自動的に検出・アラートします。

**アカウント別セキュリティ設定**

**本番環境アカウント（24アカウント）**
- **厳格なアクセス制御**：本番環境への変更は承認制とし、計画外の変更や不正な変更を防止します。変更諮問委員会（CAB）による事前レビューと、自動化されたデプロイメントパイプラインにより、人的介入を最小化します。
- **データ暗号化**：保存時・転送時の完全暗号化により、データ漏洩時も内容の保護を保証します。KMSによる暗号鍵の集中管理と、自動ローテーションにより、長期的な暗号化の安全性を維持します。
- **監査ログ**：全操作の完全記録と長期保存（7年）により、コンプライアンス要件を満たし、インシデント調査を可能にします。ログの完全性はCloudTrail Log File Validationにより保証され、改ざんを検出可能にします。
- **変更管理**：全変更の事前承認と影響評価により、変更に起因する障害やセキュリティインシデントを防止します。自動化されたロールバック機能により、問題発生時の迅速な復旧を可能にします。

**開発・テスト環境アカウント（96アカウント）**
- **開発者権限**：必要最小限の権限付与により、開発環境での事故や不正操作の影響を限定します。サンドボックス環境では自由度を高めつつ、ステージング環境では本番に準じた制限を適用する段階的アプローチを採用します。
- **データマスキング**：本番データの機密性保護により、開発環境経由でのデータ漏洩を防止します。自動化されたデータマスキングパイプラインにより、個人情報や機密情報を現実的なテストデータに置換します。
- **アクセス時間制限**：業務時間外のアクセス制限により、不正アクセスの機会を削減します。開発者の勤務パターンを学習し、異常な時間帯のアクセスを自動的に検出・ブロックします。
- **定期的なリソース削除**：不要リソースの自動削除により、攻撃対象となる放置されたリソースを排除します。30日間使用されていないリソースは自動的に削除され、コスト削減とセキュリティ向上を同時に実現します。

## 3. Identity and Access Management（IAM）統合セキュリティ

### IAM Identity Center統合認証

**フェデレーション認証基盤**

認証フロー：
```
Active Directory → IAM Identity Center → 120アカウント
├── SAML 2.0 認証（業界標準プロトコル）
├── グループベースの権限付与（管理の簡素化）
├── 条件付きアクセス（時間・場所・デバイス）
└── セッション管理（自動タイムアウト）
```

このフローにより、既存のAD基盤を活用しながら、クラウド環境に最適化された認証・認可を実現します。シングルサインオン（SSO）により、ユーザビリティとセキュリティを両立させます。

### Permission Set設計とセキュリティ制御

**管理者権限セット（厳格な制御）**

```json
{
  "OrganizationAdmin": {
    "AccessLevel": "Full",
    "MFA": "Required",
    "SessionDuration": "4時間",
    "IPRestriction": "本社IPのみ",
    "TimeRestriction": "業務時間のみ",
    "ApprovalRequired": "Yes",
    "JustInTimeAccess": "Enabled",
    "BreakGlassProcedure": "Defined"
  },
  "SecurityAdmin": {
    "AccessLevel": "SecurityServices",
    "MFA": "Required", 
    "SessionDuration": "8時間",
    "IPRestriction": "セキュリティチームIPのみ",
    "AuditLogging": "Enhanced",
    "PrivilegedAccessManagement": "Required",
    "SessionRecording": "Enabled"
  }
}
```

管理者権限は多要素認証、IP制限、時間制限、承認プロセスなど、多層的な制御により保護されます。Just-In-Time（JIT）アクセスにより、必要な時にのみ権限を付与し、常時の高権限保持を回避します。

**開発者権限セット（環境別制御）**

```json
{
  "DeveloperFull": {
    "AccessLevel": "DevelopmentEnvironment",
    "MFA": "Required",
    "SessionDuration": "8時間",
    "ResourceLimits": "開発環境のみ",
    "CostControl": "月次予算制限",
    "ServiceQuotas": "定義済み",
    "TaggingPolicy": "必須"
  },
  "DeveloperRead": {
    "AccessLevel": "ReadOnly",
    "MFA": "Optional",
    "SessionDuration": "8時間",
    "ResourceScope": "開発環境のみ",
    "DataAccess": "マスク済みデータのみ",
    "LogAccess": "自己分のみ"
  }
}
```

開発者は担当環境のみにアクセス可能とし、本番環境への誤操作を防止します。コスト制御により、意図しない高額請求を防ぎ、予算管理を徹底します。

### サービスロールセキュリティ設計

**ECS Task Role最小権限設計**

```json
{
  "20マイクロサービス別TaskRole": {
    "manufacturing-planning": {
      "DatabaseAccess": "aurora-prod-manufacturing-planning のみ",
      "S3Access": "専用バケットのみ",
      "SecretsManager": "専用シークレットのみ",
      "CloudWatchLogs": "専用ロググループのみ",
      "CrossServiceCommunication": "明示的に許可されたAPIのみ",
      "NetworkAccess": "必要なエンドポイントのみ"
    },
    "sales-order": {
      "DatabaseAccess": "aurora-prod-sales-order のみ",
      "CrossServiceAPI": "inventory-check API のみ",
      "S3Access": "専用バケットのみ", 
      "SecretsManager": "専用シークレットのみ",
      "EventBridge": "特定のイベントバスのみ",
      "SQS": "専用キューのみ"
    }
  }
}
```

各マイクロサービスは専用のリソースのみにアクセス可能とし、サービス間の不正アクセスを防止します。これにより、一つのサービスが侵害されても、他のサービスへの影響を最小限に抑えます。

**IAM Database認証セキュリティ**

```
Aurora IAM認証フロー：
ECS Task → IAM Role → Database Token (15分有効)
├── トークン自動ローテーション（有効期限管理）
├── 接続時間制限（長時間接続の防止）
├── 接続数制限（リソース枯渇攻撃の防止）
└── 全接続の監査ログ記録（異常検知）
```

短期間有効なトークンにより、認証情報の長期保存リスクを排除します。データベースパスワードの管理が不要となり、認証情報の漏洩リスクを大幅に削減します。

## 4. ネットワークセキュリティ（多層防御）

### VPC セキュリティ設計

**ネットワーク分離とセキュリティ境界**

VPC分離戦略（120アカウント）：
```
管理系VPC (10.200.0.0/16)
├── Security Account VPC（セキュリティ監視専用）
├── Shared Services VPC（共通サービス提供）
└── Network Hub VPC（接続性管理）

事業部門VPC (10.0.0.0/8)
├── 製造部門 (10.0.0.0/14)（24アカウント）
├── 販売部門 (10.1.0.0/14)（24アカウント）
├── サービス部門 (10.2.0.0/14)（24アカウント）
└── IoT部門 (10.3.0.0/14)（24アカウント）
```

この階層的な分離により、部門間の不正アクセスを防止し、侵害時の影響範囲を限定します。各VPCは独立したセキュリティ境界を形成し、明示的に許可された通信のみが可能です。

セキュリティ制御：
- プライベートサブネット中心の設計により、インターネットからの直接攻撃を防止。パブリックサブネットは最小限に抑え、必要な場合のみロードバランサーやNATゲートウェイに使用します。
- NATゲートウェイ経由の外部通信により、アウトバウンド通信を制御・監視。すべての外部通信はログ記録され、異常な通信パターンを検出可能です。
- VPC Endpoint による AWS サービスアクセスにより、インターネット経由の通信を排除。S3、DynamoDB、その他のAWSサービスへのアクセスは、プライベート接続を使用してセキュリティを向上させます。
- Transit Gateway による制御された相互接続により、必要最小限の通信のみを許可。ルートテーブルとセキュリティグループの組み合わせにより、きめ細かいアクセス制御を実現します。

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
          "Description": "ALB からのHTTPS通信のみ",
          "RateLimiting": "1000 req/sec",
          "GeoRestriction": "Japan, US, EU"
        }
      ],
      "OutboundRules": [
        {
          "Protocol": "HTTP",
          "Port": 8080,
          "Destination": "app-tier-sg",
          "Description": "アプリケーション層への通信"
        }
      ]
    },
    "app-tier-sg": {
      "InboundRules": [
        {
          "Protocol": "HTTP",
          "Port": 8080,
          "Source": "web-tier-sg",
          "Description": "Web層からのHTTP通信のみ",
          "ConnectionLimit": "10000",
          "IdleTimeout": "300 seconds"
        }
      ],
      "OutboundRules": [
        {
          "Protocol": "MySQL",
          "Port": 3306,
          "Destination": "db-tier-sg",
          "Description": "データベース層への通信"
        }
      ]
    },
    "db-tier-sg": {
      "InboundRules": [
        {
          "Protocol": "MySQL",
          "Port": 3306,
          "Source": "app-tier-sg",
          "Description": "App層からのMySQL通信のみ",
          "MaxConnections": "1000",
          "SSLRequired": true
        }
      ],
      "OutboundRules": "Deny All"
    }
  }
}
```

最小権限の原則に基づき、各層間の通信を必要最小限に制限します。アウトバウンドルールも明示的に定義し、データ流出のリスクを最小化します。

### Network Firewall実装

**ステートフルファイアウォール設定**

```yaml
# Network Firewall Rule Groups
StatefulRuleGroups:
  - Name: "malware-protection"
    Priority: 100
    Capacity: 1000
    Rules:
      - Action: "DROP"
        Header:
          Protocol: "TCP"
          Source: "ANY"
          Destination: "ANY"
        RuleOptions:
          - Keyword: "content"
            Values: ["malware-signature-patterns"]
          - Keyword: "pcre"
            Values: ["/malicious.*pattern/i"]
        SID: 1000001
        
  - Name: "intrusion-detection"
    Priority: 200
    Capacity: 2000
    Rules:
      - Action: "ALERT"
        Header:
          Protocol: "TCP"
          Source: "ANY"
          Destination: "ANY"
          DestinationPort: "ANY:1023"
        RuleOptions:
          - Keyword: "sid"
            Values: ["1001"]
          - Keyword: "msg"
            Values: ["Suspicious network activity detected"]
          - Keyword: "flow"
            Values: ["to_server,established"]
```

既知の攻撃パターンを検出・ブロックし、新たな脅威についてもアラートを生成します。Suricata互換のルール形式により、業界標準の脅威インテリジェンスを活用できます。

**ドメインフィルタリング設定**

```json
{
  "DomainFiltering": {
    "AllowedDomains": [
      "*.amazonaws.com",
      "*.technova.com",
      "github.com",
      "registry.npmjs.org",
      "docker.io",
      "pypi.org"
    ],
    "BlockedCategories": [
      "malware",
      "phishing",
      "gambling",
      "adult-content",
      "cryptocurrency-mining",
      "anonymizers"
    ],
    "CustomBlockList": [
      "known-malicious-domains.txt",
      "cryptocurrency-mining-sites.txt",
      "command-and-control-servers.txt"
    ],
    "DNSFirewallRules": {
      "QueryLogging": "Enabled",
      "ResponseValidation": "Enabled",
      "CachePositiveResponses": "300 seconds"
    }
  }
}
```

業務に必要なドメインのみを許可し、マルウェア感染やデータ漏洩のリスクを低減します。DNS over HTTPSへの対応により、暗号化されたDNS通信も制御可能です。

## 5. Web Application Firewall（WAF）統合保護

### WAF設定とルール管理

**多層WAF配置**

```
WAF配置戦略：
CloudFront → WAF (Global)
├── DDoS Protection（L3/L4/L7攻撃対策）
├── Geo-blocking（地理的制限）
├── Rate Limiting（レート制限）
└── Bot Management（ボット対策）

ALB → WAF (Regional)
├── Application-specific Rules（アプリ固有ルール）
├── Custom Rules（カスタムルール）
├── Managed Rule Groups（マネージドルール）
└── IP Reputation Lists（IP評価リスト）

API Gateway → WAF (API Protection)
├── API-specific Rules（API固有ルール）
├── Request Validation（リクエスト検証）
├── Rate Limiting per API Key（APIキー別制限）
└── Payload Inspection（ペイロード検査）
```

各層で異なる種類の攻撃に対する防御を実装し、多層防御を実現します。CloudFrontでグローバルな攻撃を防ぎ、ALBでアプリケーション固有の攻撃を防御し、API Gatewayで API 乱用を防止します。

**WAF ルール設定**

```json
{
  "WAFRuleGroups": {
    "AWSManagedRules": {
      "CommonRuleSet": {
        "Enabled": true,
        "Priority": 1,
        "OverrideAction": "None",
        "ExcludedRules": [],
        "ScopeDownStatement": null,
        "Version": "Version_1.2"
      },
      "KnownBadInputsRuleSet": {
        "Enabled": true,
        "Priority": 2,
        "OverrideAction": "None",
        "CustomResponse": {
          "ResponseCode": 403,
          "CustomResponseBody": "Access Denied"
        }
      },
      "SQLiRuleSet": {
        "Enabled": true,
        "Priority": 3,
        "OverrideAction": "None",
        "SensitivityLevel": "HIGH",
        "ManagedRuleGroupConfig": {
          "LoginPath": "/api/login",
          "PayloadType": "JSON"
        }
      },
      "XSSRuleSet": {
        "Enabled": true,
        "Priority": 4,
        "OverrideAction": "None",
        "TextTransformations": [
          "URL_DECODE",
          "HTML_ENTITY_DECODE",
          "LOWERCASE"
        ]
      }
    },
    "CustomRules": {
      "RateLimitRule": {
        "Priority": 10,
        "Action": "Block",
        "Statement": {
          "RateBasedStatement": {
            "Limit": 1000,
            "AggregateKeyType": "IP",
            "ScopeDownStatement": {
              "ByteMatchStatement": {
                "SearchString": "/api/",
                "FieldToMatch": {
                  "UriPath": {}
                },
                "TextTransformations": [{
                  "Priority": 0,
                  "Type": "LOWERCASE"
                }],
                "PositionalConstraint": "STARTS_WITH"
              }
            }
          }
        },
        "VisibilityConfig": {
          "SampledRequestsEnabled": true,
          "CloudWatchMetricsEnabled": true,
          "MetricName": "RateLimitRule"
        }
      },
      "GeoBlockRule": {
        "Priority": 11,
        "Action": "Block",
        "Statement": {
          "NotStatement": {
            "Statement": {
              "GeoMatchStatement": {
                "CountryCodes": ["JP", "US", "GB", "DE", "FR"]
              }
            }
          }
        },
        "CustomResponse": {
          "ResponseCode": 403,
          "ResponseHeaders": {
            "x-blocked-by": "geo-restriction"
          }
        }
      },
      "IPReputationRule": {
        "Priority": 12,
        "Action": "Block",
        "Statement": {
          "IPSetReferenceStatement": {
            "ARN": "arn:aws:wafv2:region:account:ipset/malicious-ips"
          }
        }
      }
    }
  }
}
```

AWS管理ルールで基本的な脅威を防御し、カスタムルールで組織固有の要件に対応します。ルールの優先順位を適切に設定し、パフォーマンスへの影響を最小化します。

### DDoS Protection統合

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
    - Global Accelerator
    
  DDoSResponseTeam:
    - 24/7 Support Access
    - Incident Response Automation
    - Emergency Escalation Procedures
    - Proactive Engagement
    
  AdvancedProtection:
    - Application Layer DDoS Protection
    - Attack Analytics and Reporting
    - Cost Protection Guarantee
    - Real-time Attack Visibility
    - Custom Mitigation
    
  AutomatedMitigation:
    - Threshold: "5x baseline traffic"
    - Actions:
      - "Enable rate limiting"
      - "Activate geo-blocking"
      - "Scale resources"
      - "Notify security team"
```

Shield Advancedにより、大規模なDDoS攻撃からの保護と、攻撃時のコスト保護を実現します。DDoS Response Team (DRT)との連携により、高度な攻撃にも対応可能です。

## 6. 通信暗号化とTLS管理

### エンドツーエンド暗号化戦略

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
        "TLS_AES_128_GCM_SHA256",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES128-GCM-SHA256"
      ],
      "EllipticCurves": [
        "P-256",
        "P-384",
        "X25519"
      ],
      "CertificateAuthority": "AWS Certificate Manager",
      "CertificateValidation": "DNS validation",
      "AutomaticRenewal": "有効",
      "CertificateTransparency": "必須",
      "OCSPStapling": "有効"
    },
    "通信フロー別暗号化": {
      "External_to_AWS": {
        "ClientToCloudFront": "TLS 1.3",
        "CloudFrontToOrigin": "TLS 1.2以上",
        "CustomHeaders": "暗号化必須",
        "OriginProtocolPolicy": "https-only",
        "ViewerProtocolPolicy": "redirect-to-https"
      },
      "Internal_AWS_Services": {
        "ALBToECS": "TLS 1.2以上",
        "ECSToAurora": "TLS 1.2 + IAM認証",
        "ServiceToService": "mTLS (相互認証)",
        "VPCEndpoint": "TLS 1.2以上",
        "PrivateLink": "TLS 1.2以上"
      },
      "Hybrid_OnPremises": {
        "DirectConnect": "MACsec暗号化",
        "VPN": "IPSec AES-256",
        "ApplicationLayer": "TLS 1.3",
        "BackupReplication": "TLS 1.2 + 追加暗号化"
      }
    }
  }
}
```

全ての通信経路で強力な暗号化を実装し、盗聴や改ざんを防止します。TLS 1.3の採用により、ハンドシェイクの高速化とセキュリティの向上を同時に実現します。

### マイクロサービス間通信暗号化

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
      CertificateRevocation: "CRL + OCSP"
      
  API_Gateway_Integration:
    UpstreamTLS: "TLS 1.2 minimum"
    DownstreamTLS: "TLS 1.3 preferred"
    CertificatePinning: "Enabled for critical services"
    BackendAuthentication: "mTLS + API Keys"
    
  Database_Connections:
    Aurora_MySQL:
      SSL_Mode: "REQUIRED"
      SSL_Cipher: "AES256-SHA256"
      CertificateVerification: "VERIFY_IDENTITY"
      ConnectionPooling: "Encrypted"
      
  Message_Queues:
    SQS: 
      Encryption: "Server-side encryption with KMS"
      MessageIntegrity: "SHA-256 HMAC"
    SNS: 
      Encryption: "Message encryption in transit and at rest"
      SignatureVersion: "4"
    EventBridge:
      Encryption: "TLS 1.2 for all event delivery"
      EventPattern: "Encrypted at rest"
```

マイクロサービス間でも相互認証と暗号化を実装し、内部ネットワークでの攻撃を防止します。Service Meshパターンの採用により、暗号化処理をアプリケーションから分離し、一貫性を確保します。

### 証明書管理とローテーション

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
          "RenewalEligibility": "365 days",
          "UsedBy": ["CloudFront", "ALB", "API Gateway"],
          "NotificationChannels": ["SNS", "Email"],
          "BackupCertificate": "Standby in us-east-1"
        },
        "api.technova.com": {
          "Type": "Single Domain Certificate",
          "ValidationMethod": "DNS",
          "AutoRenewal": true,
          "KeyAlgorithm": "EC_prime256v1",
          "UsedBy": ["API Gateway", "ECS Services"],
          "CAA_Record": "amazon.com"
        }
      },
      "PrivateCertificates": {
        "internal.technova.local": {
          "Type": "Private CA Certificate",
          "IssuingCA": "AWS Private Certificate Authority",
          "UsedBy": ["Internal Service Communication"],
          "ValidityPeriod": "1 year",
          "Template": "EndEntityCertificate",
          "PathLength": 0,
          "RevocationConfiguration": {
            "CRL": "Enabled",
            "OCSP": "Enabled"
          }
        }
      }
    },
    "マイクロサービス別証明書": {
      "manufacturing-planning.internal": {
        "Type": "Service-specific certificate",
        "RotationSchedule": "Quarterly",
        "Subject": "CN=manufacturing-planning,O=TechNova,C=JP"
      },
      "sales-order.internal": {
        "Type": "Service-specific certificate",
        "RotationSchedule": "Quarterly",
        "Subject": "CN=sales-order,O=TechNova,C=JP"
      },
      "inventory-management.internal": {
        "Type": "Service-specific certificate",
        "RotationSchedule": "Quarterly",
        "Subject": "CN=inventory-management,O=TechNova,C=JP"
      }
    }
  }
}
```

自動更新により証明書の期限切れを防止し、サービス停止リスクを排除します。Private CAを使用した内部通信の証明書管理により、外部CAへの依存を削減します。

### VPN・DirectConnect暗号化

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
      KeyRotation: "Daily"
      FallbackOption: "IPSec over public internet"
    VirtualInterface:
      BGP_MD5: "Enabled"
      BGP_Password: "Complex 32-character password"
      VLAN_Encryption: "802.1AE MACsec"
      JumboFrames: "9000 MTU"
      
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
      DPD_Timeout: "30 seconds"
      DPD_Interval: "10 seconds"
      RekeyMarginTime: "540 seconds"
      
  Client_VPN:
    Protocol: "OpenVPN"
    Cipher: "AES-256-GCM"
    Auth: "SHA-256"
    Certificate_Authentication: "Mutual authentication"
    AdditionalAuthentication: "Active Directory"
    ConnectionLogging: "CloudWatch Logs"
    SplitTunnel: "Disabled"
    SessionDuration: "8 hours"
```

オンプレミスとの接続でも最高レベルの暗号化を実装し、通信の機密性を保証します。MACsecによるレイヤー2暗号化により、DirectConnect上のすべての通信を保護します。

### アプリケーション層暗号化

**データフロー暗号化**

```json
{
  "ApplicationLayerEncryption": {
    "API通信": {
      "REST_APIs": {
        "Protocol": "HTTPS only",
        "TLS_Version": "1.3",
        "HSTS": "Enabled",
        "HSTS_MaxAge": "31536000",
        "Certificate_Transparency": "Enabled",
        "APIKey_Encryption": "AES-256",
        "RequestSigning": "AWS Signature V4"
      },
      "GraphQL_APIs": {
        "Transport": "HTTPS/WSS",
        "Query_Encryption": "Field-level encryption for sensitive data",
        "Response_Encryption": "Conditional based on data classification",
        "Persisted_Queries": "Signed with HMAC",
        "Subscription_Security": "JWT with short expiry"
      },
      "gRPC_Services": {
        "Transport": "HTTP/2 over TLS",
        "Application_Layer_Protocol_Negotiation": "Enabled",
        "Connection_Multiplexing": "Encrypted streams",
        "ChannelCredentials": "TLS + Call credentials",
        "Compression": "Disabled for sensitive data"
      }
    },
    "WebSocket通信": {
      "Protocol": "WSS (WebSocket Secure)",
      "TLS_Version": "1.3",
      "Message_Level_Encryption": "Additional AES-256 for sensitive payloads",
      "Authentication": "JWT in connection header",
      "HeartbeatInterval": "30 seconds",
      "IdleTimeout": "300 seconds"
    },
    "ファイル転送": {
      "S3_Upload": {
        "TransferEncryption": "TLS 1.2",
        "ServerSideEncryption": "SSE-KMS",
        "MultipartUpload": "Encrypted parts",
        "TransferAcceleration": "Enabled with encryption"
      },
      "Direct_Upload": {
        "Method": "Multipart upload with encryption",
        "ChunkSize": "5MB encrypted chunks",
        "Integrity": "SHA-256 per chunk"
      },
      "Pre_signed_URLs": {
        "Expiration": "15 minutes",
        "Protocol": "HTTPS only",
        "IPRestriction": "Enabled",
        "AdditionalAuth": "Required"
      }
    }
  }
}
```

アプリケーション層でも追加の暗号化を実装し、多層防御を実現します。フィールドレベル暗号化により、特に機密性の高いデータを追加保護します。

### 暗号化監視・検証

**TLS監視とコンプライアンス**

```yaml
# TLS Monitoring and Compliance
TLSMonitoring:
  Certificate_Monitoring:
    - Expiration_Alerts: "30, 14, 7, 3, 1 days before expiration"
    - Certificate_Health_Checks: "Daily SSL Labs scans"
    - Weak_Cipher_Detection: "Automated scanning every 6 hours"
    - Mixed_Content_Detection: "HTTP resources on HTTPS pages"
    - Certificate_Chain_Validation: "Complete chain verification"
    - CAA_Record_Monitoring: "DNS CAA compliance check"
    
  TLS_Configuration_Compliance:
    - Config_Rules:
        - "alb-tls-1-2-required"
        - "cloudfront-tls-1-2-required"
        - "api-gateway-tls-1-2-required"
        - "rds-encryption-enabled"
        - "elasticsearch-encrypted-at-rest"
    - Custom_Checks:
        - "Verify cipher suite compliance"
        - "Check certificate chain validity"
        - "Validate OCSP stapling"
        - "Confirm HSTS headers"
        - "Test for SSL stripping vulnerabilities"
        
  Traffic_Analysis:
    - Encrypted_Traffic_Percentage: "Target: 100%"
    - Unencrypted_Detection: "Immediate alerts"
    - TLS_Handshake_Failures: "Trending analysis"
    - Performance_Impact: "Latency monitoring"
    - Protocol_Downgrade_Attempts: "Detection and blocking"
    - Certificate_Validation_Errors: "Root cause analysis"
```

暗号化の実装状況を継続的に監視し、セキュリティレベルを維持します。SSL Labs統合により、業界標準のセキュリティ評価を自動化します。

### 暗号化キー管理統合

**KMS統合暗号化**

```json
{
  "EncryptionKeyManagement": {
    "通信暗号化キー階層": {
      "TLS_Certificates": {
        "KeyType": "RSA-2048 or EC P-256",
        "Management": "AWS Certificate Manager",
        "Rotation": "Automatic",
        "HSM_Backed": "CloudHSM for root CA"
      },
      "Application_Level_Keys": {
        "KeyType": "AES-256",
        "Management": "AWS KMS",
        "Usage": "Field-level encryption",
        "Rotation": "Annual",
        "MultiRegion": "Enabled for DR",
        "KeyPolicy": "Least privilege access"
      },
      "Service_Communication_Keys": {
        "KeyType": "EC P-256",
        "Management": "AWS Private CA",
        "Usage": "mTLS certificates",
        "Rotation": "Quarterly",
        "Distribution": "Secrets Manager",
        "Audit": "CloudTrail integration"
      }
    },
    "キーガバナンス": {
      "KeyAccess": "Role-based with least privilege",
      "KeyAuditing": "All key usage logged in CloudTrail",
      "KeyRotation": "Automated with business approval",
      "KeyRecovery": "Secure backup and recovery procedures",
      "KeyDeletion": "30-day waiting period with MFA",
      "ComplianceReporting": "Automated compliance dashboards"
    }
  }
}
```

階層的なキー管理により、適切なアクセス制御と監査性を実現します。マルチリージョンキーにより、災害時でも暗号化されたデータへのアクセスを確保します。

### 暗号化パフォーマンス最適化

**暗号化オーバーヘッド管理**

```yaml
# Encryption Performance Optimization
EncryptionPerformance:
  TLS_Optimization:
    - Session_Resumption: "TLS session tickets enabled"
    - Session_Cache: "Distributed cache with 1-hour TTL"
    - OCSP_Stapling: "Enabled to reduce handshake latency"
    - Hardware_Acceleration: "AWS Nitro System utilization"
    - Connection_Reuse: "HTTP/2 connection multiplexing"
    - Early_Data: "TLS 1.3 0-RTT for repeat connections"
    
  Cipher_Suite_Optimization:
    - AEAD_Ciphers: "Preferred for authenticated encryption"
    - ECDHE_Key_Exchange: "Perfect Forward Secrecy"
    - Hardware_AES: "AES-NI instruction utilization"
    - ChaCha20: "Mobile device optimization"
    - Cipher_Order: "Server-preferred order"
    
  Load_Distribution:
    - SSL_Termination: "Load balancer level"
    - Connection_Pooling: "Backend SSL connection reuse"
    - Regional_Distribution: "Edge location SSL termination"
    - CDN_Integration: "CloudFront SSL offloading"
    - Caching_Strategy: "Encrypted content caching"
```

ハードウェアアクセラレーションとセッション再利用により、暗号化のパフォーマンス影響を最小化します。AWS Nitro Systemの活用により、暗号化処理をオフロードし、アプリケーションパフォーマンスを維持します。

### 暗号化コンプライアンス

**規制要件対応**

```json
{
  "EncryptionCompliance": {
    "FIPS_140_2": {
      "Level": "Level 2 validated modules",
      "Scope": "All cryptographic operations",
      "Implementation": "AWS FIPS endpoints",
      "ValidatedModules": [
        "AWS-LC Cryptographic Module",
        "OpenSSL FIPS Object Module"
      ],
      "Documentation": "FIPS certificates maintained"
    },
    "Common_Criteria": {
      "EAL_Level": "EAL4+",
      "Validated_Components": [
        "AWS KMS",
        "CloudHSM",
        "Nitro System"
      ],
      "Certification": "Annual renewal"
    },
    "Industry_Standards": {
      "PCI_DSS": {
        "Requirement": "Strong cryptography for cardholder data",
        "Implementation": "TLS 1.2+, AES-256",
        "KeyManagement": "Split knowledge and dual control"
      },
      "GDPR": {
        "Requirement": "Appropriate technical measures",
        "Implementation": "Encryption by default",
        "RightToErasure": "Crypto-shredding capability"
      },
      "HIPAA": {
        "Requirement": "Encryption of PHI in transit",
        "Implementation": "End-to-end encryption",
        "Audit": "Access logging for all PHI"
      }
    },
    "国内規制": {
      "個人情報保護法": {
        "要件": "個人データの安全管理措置",
        "実装": "暗号化による技術的保護",
        "監査": "定期的な有効性評価"
      },
      "サイバーセキュリティ基本法": {
        "要件": "重要インフラの保護",
        "実装": "多層暗号化戦略",
        "報告": "インシデント時の報告体制"
      }
    }
  }
}
```

各種規制要件に準拠した暗号化実装により、コンプライアンスリスクを排除します。FIPS 140-2準拠モードの選択により、政府機関の要件にも対応可能です。

## 7. コンテナセキュリティ（ECS/ECR）

### ECR セキュリティ設定

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
      },
      "ScanningScope": {
        "OS_Packages": true,
        "Application_Dependencies": true,
        "Binary_Files": true,
        "License_Compliance": true
      },
      "Integration": {
        "Snyk": "Enabled",
        "Twistlock": "Enabled",
        "CustomScanner": "Internal security scanner"
      }
    },
    "ImageImmutability": true,
    "ImageSignature": {
      "Required": true,
      "SigningProfile": "arn:aws:signer:region:account:profile",
      "TrustPolicy": "Verified publishers only"
    },
    "Encryption": {
      "Type": "KMS",
      "KMSKey": "service-specific-key",
      "Algorithm": "AES-256-GCM"
    },
    "LifecyclePolicy": {
      "UntaggedImages": "Delete after 7 days",
      "TaggedImages": "Keep latest 10 versions",
      "VulnerableImages": "Quarantine and notify",
      "ProductionImages": "Preserve with backup"
    }
  }
}
```

プッシュ時と継続的なスキャンにより、脆弱性のあるイメージの使用を防止します。イメージの署名により、信頼できるソースからのイメージのみを使用することを保証します。

**脆弱性管理自動化**

```yaml
# Container Security Automation
VulnerabilityManagement:
  Detection:
    - Continuous Image Scanning
    - Runtime Vulnerability Assessment
    - Third-party Security Integration
    - SBOM (Software Bill of Materials) Generation
    - License Compliance Checking
    
  Response:
    - Automated Patch Deployment
    - Image Rebuild Triggers
    - Security Alert Notifications
    - Vulnerability Exception Management
    - Risk Score Calculation
    
  Compliance:
    - CIS Benchmark Compliance
    - NIST Container Security Guidelines
    - Industry Best Practices
    - Custom Security Policies
    - Audit Trail Generation
    
  Remediation:
    - AutoPatch: "Non-breaking security updates"
    - RebuildTrigger: "Critical vulnerabilities"
    - Notification: "Security and Dev teams"
    - Tracking: "JIRA integration"
    - Validation: "Post-patch testing"
```

脆弱性の検出から修復まで自動化し、セキュリティレベルを継続的に維持します。SBOMの生成により、サプライチェーンの透明性を確保します。

#### ECS Runtime セキュリティ

**コンテナランタイム保護**

```json
{
  "ECSSecurityConfiguration": {
    "TaskDefinitionSecurity": {
      "Privileged": false,
      "ReadOnlyRootFilesystem": true,
      "User": "non-root",
      "NetworkMode": "awsvpc",
      "RequireCompatibilities": ["FARGATE"],
      "RuntimePlatform": {
        "OperatingSystemFamily": "LINUX",
        "CpuArchitecture": "X86_64"
      },
      "ProxyConfiguration": {
        "Type": "APPMESH",
        "ContainerName": "envoy",
        "Properties": {
          "IgnoredUID": "1337",
          "ProxyIngressPort": "15000",
          "ProxyEgressPort": "15001"
        }
      }
    },
    "SecretsManagement": {
      "SecretProvider": "AWS Secrets Manager",
      "AutoRotation": true,
      "EncryptionInTransit": true,
      "VersionStaging": ["AWSCURRENT", "AWSPENDING"],
      "AccessControl": "Task role specific"
    },
    "LogConfiguration": {
      "LogDriver": "awslogs",
      "LogGroup": "/ecs/security-enhanced",
      "LogRetention": "30 days",
      "StreamPrefix": "ecs",
      "SecretOptions": {
        "awslogs-endpoint": "Encrypted"
      }
    },
    "ResourceLimits": {
      "CPU": "256-4096",
      "Memory": "512-8192",
      "EphemeralStorage": "20-200 GB",
      "GPUs": "As required"
    }
  }
}
```

最小権限の原則に基づいたコンテナ実行により、攻撃面を最小化します。読み取り専用ルートファイルシステムにより、ランタイム時のファイル改ざんを防止します。

**Service Connect セキュリティ**

```yaml
# Service Connect Security Configuration
ServiceConnectSecurity:
  Encryption:
    - Protocol: "TLS 1.3"
    - CertificateProvider: "AWS Certificate Manager"
    - CertificateRotation: "Automatic (90 days)"
    - MutualTLS: "Required for service communication"
    
  Authentication:
    - Method: "mTLS + JWT"
    - IdentityProvider: "IAM Roles for Service Accounts"
    - TokenValidation: "Strict with short expiry"
    - ServiceMesh: "AWS App Mesh integration"
    
  Authorization:
    - PolicyEngine: "OPA (Open Policy Agent)"
    - PolicyLanguage: "Rego"
    - DecisionLogging: "CloudWatch Logs"
    - PolicyUpdates: "GitOps workflow"
    
  Monitoring:
    - TrafficFlow: "X-Ray service map"
    - AnomalyDetection: "CloudWatch Anomaly Detector"
    - SecurityEvents: "GuardDuty container protection"
    - Metrics: "CloudWatch Container Insights"
    
  NetworkPolicies:
    - DefaultDeny: "All ingress/egress blocked by default"
    - ExplicitAllow: "Whitelist specific service communications"
    - NamespaceIsolation: "Logical separation of services"
    - NetworkSegmentation: "Microsegmentation per service"
```

サービス間通信の暗号化と認証により、内部ネットワークでの攻撃を防止します。Service Meshパターンにより、セキュリティポリシーを一元管理します。

**コンテナイメージのセキュアビルド**

```yaml
# Secure Container Build Pipeline
SecureBuildPipeline:
  SourceCodeSecurity:
    - StaticAnalysis: "SonarQube, Checkmarx"
    - DependencyCheck: "OWASP Dependency Check"
    - SecretScanning: "TruffleHog, GitLeaks"
    - LicenseCompliance: "WhiteSource, Black Duck"
    
  BuildEnvironment:
    - IsolatedBuilders: "Dedicated build accounts"
    - EphemeralEnvironment: "Destroyed after build"
    - NetworkRestriction: "No internet during build"
    - AuditLogging: "All build actions logged"
    
  ImageConstruction:
    - BaseImage: "Minimal distroless images"
    - MultiStageBuilds: "Separate build and runtime"
    - LayerOptimization: "Minimize attack surface"
    - SecurityHardening: "Remove unnecessary tools"
    
  Validation:
    - SecurityTesting: "Container structure tests"
    - ComplianceChecks: "CIS benchmark validation"
    - SignatureVerification: "Image signing required"
    - PolicyValidation: "OPA policy checks"
```

セキュアなビルドパイプラインにより、ソースコードから本番環境まで一貫したセキュリティを確保します。Distrolessイメージの採用により、攻撃面を大幅に削減します。