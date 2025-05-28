# セキュリティ要件 Part 3: セクション16-22（高度なセキュリティと改善）

## 16. 新技術・脅威への対応

### 実装対象サービス

**Amazon GuardDuty（脅威インテリジェンス）**
- カスタム脅威インテリジェンスフィードの統合により、業界固有の脅威に対応します。TechNova社の産業機械分野特有の脅威情報を取り込み、標的型攻撃への検知精度を向上させます。
- 既知の安全なIPリストにより、誤検知を削減します。本社、工場、取引先のIPアドレスをホワイトリストに登録し、正常な業務活動が脅威として検出されることを防ぎます。

**AWS Lambda（脅威分析・自動対応）**
- 検知された脅威に対する自動対応ロジックを実装し、初動対応を高速化します。例えば、不審なEC2インスタンスの自動隔離、侵害されたIAMクレデンシャルの無効化を数秒以内に実行します。
- 脅威インテリジェンスの自動更新により、最新の脅威情報を活用します。MITRE ATT&CKフレームワークと連携し、攻撃手法を体系的に分析・対応します。

**Amazon S3（脅威インテリジェンスデータ保存）**
- 脅威情報の一元管理により、組織全体での脅威情報共有を実現します。過去の攻撃パターンや対応履歴を蓄積し、将来の攻撃への対応力を向上させます。
- 暗号化とアクセス制御により、機密性の高い脅威情報を保護します。脅威情報の漏洩は攻撃者に有利な情報を与えるため、厳格な管理を実施します。

**Amazon EventBridge（イベント処理）**
- セキュリティイベントの統合処理により、複数のソースからのイベントを一元的に処理します。GuardDuty、Security Hub、カスタムアプリケーションからのイベントを統合し、包括的な対応を実現します。
- ルールベースの自動処理により、イベントの種類に応じた適切な対応を自動実行します。重要度に応じた通知、自動修復、エスカレーションを実装します。

**Amazon Comprehend（AI分析）**
- セキュリティイベントの自然言語処理により、高度な脅威分析を実現します。ログメッセージのパターン分析により、人間では見逃しがちな微細な異常を検出します。
- 過去のインシデントデータを学習し、類似パターンの早期発見を可能にします。攻撃の兆候を早期に検出し、被害を未然に防ぎます。

### Terraform実装コード

```hcl
# 脅威インテリジェンス用 S3 バケット
resource "aws_s3_bucket" "threat_intelligence" {
  bucket = "technova-threat-intel-${data.aws_caller_identity.current.account_id}"
  
  tags = {
    Purpose            = "Threat Intelligence Storage"
    DataClassification = "Confidential"
    Retention          = "7 years"
  }
}

resource "aws_s3_bucket_versioning" "threat_intel_versioning" {
  bucket = aws_s3_bucket.threat_intelligence.id
  
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "threat_intel_encryption" {
  bucket = aws_s3_bucket.threat_intelligence.id
  
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.threat_intel_key.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "threat_intel_lifecycle" {
  bucket = aws_s3_bucket.threat_intelligence.id
  
  rule {
    id     = "archive_old_intel"
    status = "Enabled"
    
    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }
    
    transition {
      days          = 365
      storage_class = "GLACIER"
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
    UpdateFrequency = "Daily"
  }
}

resource "aws_guardduty_threatintelset" "industry_threats" {
  activate    = true
  detector_id = aws_guardduty_detector.main.id
  format      = "STIX"
  location    = "s3://${aws_s3_bucket.threat_intelligence.id}/industry/manufacturing-threats.stix"
  name        = "ManufacturingIndustryThreats"
  
  tags = {
    Source = "Industry ISAC"
    UpdateFrequency = "Hourly"
  }
}

resource "aws_guardduty_ipset" "known_safe_ips" {
  activate    = true
  detector_id = aws_guardduty_detector.main.id
  format      = "TXT"
  location    = "s3://${aws_s3_bucket.threat_intelligence.id}/allowlist/safe-ips.txt"
  name        = "KnownSafeIPs"
  
  tags = {
    Purpose = "False Positive Reduction"
    UpdateMethod = "Automated"
  }
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
      EXTERNAL_FEED_URLS    = jsonencode({
        abuse_ch     = "https://urlhaus.abuse.ch/downloads/text/"
        emerging_threats = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
        alienvault   = "https://reputation.alienvault.com/reputation.generic"
      })
      MITRE_ATTACK_API      = "https://attack.mitre.org/api/v2/"
      UPDATE_FREQUENCY      = "3600" # seconds
    }
  }
  
  vpc_config {
    subnet_ids         = var.private_subnet_ids
    security_group_ids = [aws_security_group.lambda_sg.id]
  }
  
  tags = {
    Purpose = "Threat Intelligence Automation"
    Integration = "MITRE ATT&CK"
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
  
  layers = [
    "arn:aws:lambda:${var.aws_region}:336392948345:layer:AWSSDKPandas-Python39:1"
  ]
  
  environment {
    variables = {
      COMPREHEND_MODEL_ARN = aws_comprehend_document_classifier.security_classifier.arn
      ANOMALY_THRESHOLD    = "0.8"
      ALERT_SNS_TOPIC      = aws_sns_topic.ai_security_alerts.arn
      LOOKBACK_HOURS       = "24"
      ML_FEATURES = jsonencode({
        log_patterns = ["failed_auth", "privilege_escalation", "data_exfiltration"]
        behavioral_analysis = ["access_time", "resource_usage", "api_calls"]
        threat_correlation = ["ip_reputation", "geo_anomaly", "user_behavior"]
      })
    }
  }
  
  dead_letter_config {
    target_arn = aws_sqs_queue.ai_detector_dlq.arn
  }
  
  tags = {
    Purpose = "AI-Powered Threat Detection"
    MLModel = "Custom Security Classifier"
  }
}

# Amazon Comprehend セキュリティ分類モデル
resource "aws_comprehend_document_classifier" "security_classifier" {
  name                = "security-event-classifier"
  data_access_role_arn = aws_iam_role.comprehend_role.arn
  language_code       = "en"
  
  input_data_config {
    s3_uri = "s3://${aws_s3_bucket.ml_training_data.id}/security-training-data/"
    
    augmented_manifests {
      s3_uri               = "s3://${aws_s3_bucket.ml_training_data.id}/augmented-manifest/security-events.jsonl"
      attribute_names      = ["security_event_type", "threat_level"]
      document_type       = "PLAIN_TEXT_DOCUMENT"
    }
  }
  
  output_data_config {
    s3_uri = "s3://${aws_s3_bucket.ml_models.id}/comprehend/security-classifier/"
  }
  
  tags = {
    Purpose   = "Security Event Classification"
    ModelType = "DocumentClassifier"
    Version   = "2.0"
  }
}

# 脅威ハンティング用 EventBridge ルール
resource "aws_cloudwatch_event_rule" "threat_hunting_schedule" {
  name                = "automated-threat-hunting"
  description         = "Automated threat hunting every 6 hours"
  schedule_expression = "rate(6 hours)"
  
  tags = {
    Purpose = "Proactive Threat Detection"
  }
}

resource "aws_cloudwatch_event_target" "threat_hunting_target" {
  rule      = aws_cloudwatch_event_rule.threat_hunting_schedule.name
  target_id = "ThreatHuntingLambda"
  arn       = aws_lambda_function.threat_hunter.arn
  
  input_transformer {
    input_paths = {
      time = "$.time"
    }
    input_template = jsonencode({
      hunting_scope = "full_infrastructure"
      techniques    = ["T1078", "T1110", "T1190", "T1133"] # MITRE ATT&CK techniques
      time_range   = "<time>"
    })
  }
}

# 脅威ハンティング Lambda
resource "aws_lambda_function" "threat_hunter" {
  filename      = "threat_hunter.zip"
  function_name = "automated-threat-hunter"
  role          = aws_iam_role.threat_hunter_role.arn
  handler       = "index.handler"
  runtime       = "python3.9"
  timeout       = 900
  memory_size   = 2048
  
  environment {
    variables = {
      ATHENA_DATABASE       = "security_logs"
      ATHENA_WORKGROUP     = "threat_hunting"
      S3_QUERY_RESULTS     = "s3://${aws_s3_bucket.threat_hunting_results.id}/"
      HUNTING_QUERIES      = jsonencode({
        lateral_movement   = "SELECT * FROM vpc_flow_logs WHERE action='ACCEPT' AND protocol=22"
        data_exfiltration = "SELECT * FROM cloudtrail WHERE eventName LIKE '%GetObject%' GROUP BY userIdentity.arn"
        privilege_escalation = "SELECT * FROM cloudtrail WHERE eventName IN ('AssumeRole', 'AttachUserPolicy')"
      })
    }
  }
  
  tags = {
    Purpose = "Proactive Threat Hunting"
    Method  = "Behavioral Analytics"
  }
}
```

## 17. セキュリティ教育・トレーニング

### 実装対象サービス

**Amazon DynamoDB（教育記録・結果保存）**
- 従業員5,000名の教育履歴を体系的に管理し、コンプライアンス要件を満たします。受講履歴、テスト結果、認定状況を一元管理することで、監査時の証跡提供も迅速に行えます。
- フィッシングシミュレーション結果を分析し、教育効果を定量化します。クリック率、報告率、対応時間などのメトリクスにより、セキュリティ意識の向上度を客観的に測定できます。

**Amazon SES（フィッシングシミュレーション）**
- 実際の攻撃を模したフィッシングメールで、従業員の警戒心を維持します。最新の攻撃手法を反映したシミュレーションにより、実践的な訓練を提供し、実際の攻撃への対応力を向上させます。
- クリック率、報告率などのメトリクスで、セキュリティ意識を測定します。部門別、役職別の分析により、リスクの高いグループを特定し、追加教育を実施します。

**AWS Lambda（教育システム制御）**
- 教育コンテンツの自動配信により、定期的な教育を確実に実施します。新入社員への自動教育割当、年次教育の自動リマインダーにより、教育の漏れを防止します。
- 未受講者への自動リマインダーで、受講率100%を目指します。エスカレーション機能により、長期未受講者の上長へ通知し、組織全体のセキュリティレベルを向上させます。

**Amazon CloudWatch（教育メトリクス）**
- 教育プログラムの効果を可視化し、改善点を特定します。受講率、合格率、フィッシングシミュレーション成功率などを継続的に測定し、教育プログラムの最適化を図ります。
- ダッシュボードにより、経営層への報告を効率化します。セキュリティ教育の投資対効果を定量的に示し、継続的な投資を正当化します。

**Amazon S3（教育コンテンツ保存）**
- 教育コンテンツの一元管理により、最新の教材を常に提供します。動画、プレゼンテーション、クイズなど、多様な形式の教材を安全に保存・配信します。
- バージョン管理により、教材の更新履歴を追跡します。規制変更や新たな脅威に対応した教材更新を確実に実施し、常に最新の情報を提供します。

### Terraform実装コード

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
  
  attribute {
    name = "department"
    type = "S"
  }
  
  attribute {
    name = "completion_status"
    type = "S"
  }
  
  global_secondary_index {
    name            = "TrainingTypeIndex"
    hash_key        = "training_type"
    range_key       = "training_date"
    projection_type = "ALL"
  }
  
  global_secondary_index {
    name            = "DepartmentIndex"
    hash_key        = "department"
    range_key       = "completion_status"
    projection_type = "ALL"
  }
  
  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"
  
  point_in_time_recovery {
    enabled = true
  }
  
  tags = {
    Purpose       = "Security Training Management"
    DataRetention = "7years"
    Compliance    = "ISO27001"
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
  
  attribute {
    name = "campaign_id"
    type = "S"
  }
  
  global_secondary_index {
    name            = "ResultStatusIndex"
    hash_key        = "result_status"
    range_key       = "simulation_id"
    projection_type = "ALL"
  }
  
  global_secondary_index {
    name            = "CampaignIndex"
    hash_key        = "campaign_id"
    range_key       = "result_status"
    projection_type = "INCLUDE"
    non_key_attributes = ["click_time", "report_time", "training_completed"]
  }
  
  ttl {
    attribute_name = "expiry_time"
    enabled        = true
  }
  
  tags = {
    Purpose = "Phishing Simulation Analytics"
    DataPrivacy = "Anonymized after 90 days"
  }
}

# フィッシングシミュレーション用 SES 設定
resource "aws_ses_email_identity" "phishing_simulation" {
  email = "security-training@technova.com"
  
  tags = {
    Purpose = "Phishing Simulation"
    Authorized = "Security Team Only"
  }
}

resource "aws_ses_domain_identity" "phishing_domains" {
  for_each = toset([
    "technova-secure.com",
    "technova-training.com",
    "security-awareness.technova.com"
  ])
  
  domain = each.value
}

resource "aws_ses_configuration_set" "phishing_tracking" {
  name = "phishing-simulation-tracking"
  
  event_destination {
    name               = "cloudwatch-event-destination"
    enabled            = true
    matching_types     = ["send", "bounce", "complaint", "delivery", "open", "click", "renderingFailure"]
    
    cloudwatch_destination {
      default_value  = "0"
      dimension_name = "MessageTag"
      value_source   = "messageTag"
    }
  }
  
  reputation_tracking_enabled = true
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
      CAMPAIGN_CONFIG = jsonencode({
        difficulty_levels = ["basic", "intermediate", "advanced"]
        targeting_strategy = "risk_based"
        frequency = "monthly"
        personalization = true
      })
    }
  }
  
  vpc_config {
    subnet_ids         = var.private_subnet_ids
    security_group_ids = [aws_security_group.lambda_sg.id]
  }
  
  tags = {
    Purpose = "Security Training Automation"
    DataHandling = "Sensitive"
  }
}

# セキュリティ教育コンテンツ用 S3
resource "aws_s3_bucket" "training_content" {
  bucket = "technova-security-training-${data.aws_caller_identity.current.account_id}"
  
  tags = {
    Purpose = "Security Training Content"
    ContentTypes = "Video, PDF, SCORM, HTML5"
  }
}

resource "aws_s3_bucket_versioning" "training_content_versioning" {
  bucket = aws_s3_bucket.training_content.id
  
  versioning_configuration {
    status = "Enabled"
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
      },
      {
        Sid    = "DenyUnencryptedDownloads"
        Effect = "Deny"
        Principal = "*"
        Action = "s3:GetObject"
        Resource = "${aws_s3_bucket.training_content.arn}/*"
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

# 教育進捗追跡用 Lambda
resource "aws_lambda_function" "training_progress_tracker" {
  filename      = "training_progress_tracker.zip"
  function_name = "security-training-progress-tracker"
  role          = aws_iam_role.training_tracker_role.arn
  handler       = "index.handler"
  runtime       = "python3.9"
  timeout       = 300
  
  environment {
    variables = {
      TRAINING_RECORDS_TABLE = aws_dynamodb_table.security_training_records.name
      EMPLOYEE_TABLE         = aws_dynamodb_table.employee_directory.name
      NOTIFICATION_TOPIC     = aws_sns_topic.training_notifications.arn
      ESCALATION_CONFIG = jsonencode({
        reminder_intervals = [7, 14, 21]  # days
        escalation_levels = ["employee", "manager", "director"]
        completion_deadline = 30  # days
      })
    }
  }
  
  tags = {
    Purpose = "Training Compliance Tracking"
  }
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
            [
              "SecurityTraining", "CompletionRate",
              { stat = "Average", period = 86400 }
            ],
            [
              ".", "PhishingClickRate",
              { stat = "Average", period = 86400 }
            ],
            [
              ".", "SecurityIncidentReports",
              { stat = "Sum", period = 86400 }
            ]
          ]
          period = 300
          stat   = "Average"
          region = var.aws_region
          title  = "Security Training Effectiveness"
          yAxis = {
            left = {
              min = 0
              max = 100
            }
          }
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        
        properties = {
          metrics = [
            [ "SecurityTraining", "TrainingHours", "Department", "Engineering" ],
            [ "...", "Sales" ],
            [ "...", "Manufacturing" ],
            [ "...", "Administration" ]
          ]
          period = 2592000  # 30 days
          stat   = "Sum"
          region = var.aws_region
          title  = "Training Hours by Department"
        }
      }
    ]
  })
}

# 年次セキュリティ認定試験システム
resource "aws_lambda_function" "security_certification_exam" {
  filename      = "security_certification_exam.zip"
  function_name = "annual-security-certification"
  role          = aws_iam_role.certification_role.arn
  handler       = "index.handler"
  runtime       = "python3.9"
  timeout       = 600
  
  environment {
    variables = {
      QUESTION_BANK      = "s3://${aws_s3_bucket.training_content.id}/certification/questions/"
      PASSING_SCORE      = "80"
      MAX_ATTEMPTS       = "3"
      CERTIFICATE_TEMPLATE = "s3://${aws_s3_bucket.training_content.id}/certification/certificate-template.pdf"
      RESULTS_TABLE      = aws_dynamodb_table.certification_results.name
    }
  }
  
  tags = {
    Purpose = "Security Certification Management"
    Compliance = "Annual Requirement"
  }
}
```

## 18. サプライチェーンセキュリティ

### 実装対象サービス

**AWS Systems Manager（ベンダー評価管理）**
- サプライヤーのセキュリティ評価結果を一元管理し、リスクの可視化を実現します。評価基準の標準化により、客観的なベンダー選定が可能となり、サプライチェーンリスクを低減します。
- 定期的な再評価により、継続的なリスク管理を実施します。年次評価の自動化により、評価漏れを防止し、常に最新のリスク状況を把握できます。

**Amazon Inspector（コンテナ・依存関係スキャン）**
- コンテナイメージの脆弱性を継続的にスキャンし、既知の脆弱性を排除します。CVEデータベースと連携し、最新の脆弱性情報に基づく検査により、ゼロデイ攻撃のリスクを最小化します。
- 依存関係の脆弱性も含めて包括的に検査し、サプライチェーン攻撃を防ぎます。オープンソースライブラリの脆弱性も検出し、Log4jのような広範囲な影響を持つ脆弱性にも迅速に対応できます。

**AWS CodeBuild（セキュアビルドパイプライン）**
- ビルド環境を隔離し、ビルドプロセスへの不正な介入を防ぎます。各ビルドは独立した環境で実行され、ビルド間の汚染や不正なコードの混入を防止します。
- SBOM（Software Bill of Materials）を自動生成し、使用コンポーネントを追跡します。全ての依存関係を記録することで、脆弱性発覚時の影響範囲を即座に特定し、迅速な対応を可能にします。

**Amazon ECR（コンテナイメージセキュリティ）**
- イメージの不変性により、承認済みイメージのみが使用されることを保証します。タグの上書きを防止し、テスト済みのイメージが改ざんされることなくデプロイされることを保証します。
- 脆弱性レベルに応じた自動対応で、高リスクイメージの使用を防止します。Criticalレベルの脆弱性を持つイメージは自動的にブロックされ、本番環境への展開を防ぎます。

**AWS Config（サプライチェーンコンプライアンス）**
- サプライチェーン関連の設定を継続的に監視し、ポリシー違反を検出します。承認されていないレジストリからのイメージ使用や、未検証のライブラリの使用を防止します。
- 自動修復により、非準拠の設定を即座に是正します。セキュリティポリシーに違反する設定変更を自動的に元に戻し、常に安全な状態を維持します。

### Terraform実装コード

```hcl
# Inspector V2 有効化（コンテナ・EC2脆弱性スキャン）
resource "aws_inspector2_enabler" "organization" {
  account_ids    = [data.aws_caller_identity.current.account_id]
  resource_types = ["ECR", "EC2", "LAMBDA"]
}

resource "aws_inspector2_organization_configuration" "main" {
  auto_enable {
    ecr    = true
    ec2    = true
    lambda = true
  }
  
  depends_on = [aws_inspector2_enabler.organization]
}

# ECR レポジトリセキュリティ設定
resource "aws_ecr_repository" "secure_apps" {
  for_each = var.application_configs
  
  name                 = each.key
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
    Application      = each.key
    SecurityScanning = "Enabled"
    Compliance       = "Required"
  }
}

# ECR レプリケーション設定（DR対応）
resource "aws_ecr_replication_configuration" "cross_region" {
  replication_configuration {
    rule {
      destination {
        region      = var.dr_region
        registry_id = data.aws_caller_identity.current.account_id
      }
      
      repository_filter {
        filter      = "*-prod"
        filter_type = "PREFIX_MATCH"
      }
    }
  }
}

# ECR ライフサイクルポリシー（脆弱性のあるイメージ管理）
resource "aws_ecr_lifecycle_policy" "security_policy" {
  for_each   = aws_ecr_repository.secure_apps
  repository = each.value.name
  
  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Delete untagged images after 1 day"
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = 1
        }
        action = {
          type = "expire"
        }
      },
      {
        rulePriority = 2
        description  = "Keep only 10 latest production images"
        selection = {
          tagStatus   = "tagged"
          tagPrefixList = ["prod"]
          countType   = "imageCountMoreThan"
          countNumber = 10
        }
        action = {
          type = "expire"
        }
      },
      {
        rulePriority = 3
        description  = "Delete old development images"
        selection = {
          tagStatus   = "tagged"
          tagPrefixList = ["dev", "test"]
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = 30
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
    image                      = "aws/codebuild/standard:5.0"
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
    
    environment_variable {
      name  = "SBOM_GENERATION"
      value = "ENABLED"
    }
  }
  
  source {
    type      = "CODEPIPELINE"
    buildspec = "buildspec-security.yml"
  }
  
  vpc_config {
    vpc_id             = var.vpc_id
    subnets            = var.private_subnet_ids
    security_group_ids = [aws_security_group.codebuild_sg.id]
  }
  
  logs_config {
    cloudwatch_logs {
      group_name  = "/aws/codebuild/secure-builds"
      stream_name = "build-logs"
    }
    
    s3_logs {
      status   = "ENABLED"
      location = "${aws_s3_bucket.build_logs.id}/build-logs"
    }
  }
  
  tags = {
    Purpose = "Secure Software Supply Chain"
    ScanningTools = "Snyk, OWASP, Trivy"
  }
}

# buildspec-security.yml の内容を SSM Parameter に保存
resource "aws_ssm_parameter" "buildspec_security" {
  name  = "/codebuild/buildspec/security"
  type  = "SecureString"
  value = jsonencode({
    version = 0.2
    phases = {
      pre_build = {
        commands = [
          "echo 'Starting security scan phase'",
          "docker pull aquasec/trivy:latest",
          "pip install safety bandit",
          "npm install -g snyk @cyclonedx/cdxgen"
        ]
      }
      build = {
        commands = [
          # 依存関係スキャン
          "safety check --json > safety-report.json || true",
          "snyk test --json > snyk-report.json || true",
          "bandit -r . -f json -o bandit-report.json || true",
          
          # SBOM生成
          "cdxgen -o sbom.json",
          
          # コンテナイメージビルド
          "docker build -t $IMAGE_REPO_NAME:$IMAGE_TAG .",
          
          # コンテナスキャン
          "trivy image --format json --output trivy-report.json $IMAGE_REPO_NAME:$IMAGE_TAG",
          
          # 結果の評価
          "python /opt/security-evaluator.py"
        ]
      }
      post_build = {
        commands = [
          # スキャン結果をS3に保存
          "aws s3 cp safety-report.json s3://$SCAN_RESULTS_BUCKET/$CODEBUILD_BUILD_ID/",
          "aws s3 cp snyk-report.json s3://$SCAN_RESULTS_BUCKET/$CODEBUILD_BUILD_ID/",
          "aws s3 cp bandit-report.json s3://$SCAN_RESULTS_BUCKET/$CODEBUILD_BUILD_ID/",
          "aws s3 cp trivy-report.json s3://$SCAN_RESULTS_BUCKET/$CODEBUILD_BUILD_ID/",
          "aws s3 cp sbom.json s3://$SBOM_BUCKET/$IMAGE_REPO_NAME/$IMAGE_TAG/",
          
          # ECRにプッシュ（セキュリティチェックパス時のみ）
          "docker push $IMAGE_REPO_NAME:$IMAGE_TAG"
        ]
      }
    }
  })
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
  
  attribute {
    name = "vendor_type"
    type = "S"
  }
  
  global_secondary_index {
    name            = "RiskLevelIndex"
    hash_key        = "risk_level"
    range_key       = "assessment_date"
    projection_type = "ALL"
  }
  
  global_secondary_index {
    name            = "VendorTypeIndex"
    hash_key        = "vendor_type"
    range_key       = "risk_level"
    projection_type = "ALL"
  }
  
  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"
  
  tags = {
    Purpose       = "Vendor Risk Management"
    DataRetention = "7years"
    Compliance    = "SOC2"
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
  
  layers = [
    "arn:aws:lambda:${var.aws_region}:553035198032:layer:git-lambda2:7"
  ]
  
  environment {
    variables = {
      VULNERABILITY_APIS = jsonencode({
        osv         = "https://api.osv.dev/v1/query"
        snyk        = "https://api.snyk.io/v1/"
        github      = "https://api.github.com/graphql"
        nvd         = "https://services.nvd.nist.gov/rest/json/cves/2.0"
      })
      RESULTS_TABLE         = aws_dynamodb_table.dependency_scan_results.name
      SEVERITY_THRESHOLD    = "HIGH"
      AUTO_CREATE_ISSUES    = "true"
      ISSUE_TRACKER         = "JIRA"
      SBOM_BUCKET          = aws_s3_bucket.sbom_storage.id
    }
  }
  
  tags = {
    Purpose = "Software Supply Chain Security"
    Integration = "Multiple Vulnerability DBs"
  }
}

# SBOM (Software Bill of Materials) 保存用 S3
resource "aws_s3_bucket" "sbom_storage" {
  bucket = "technova-sbom-${data.aws_caller_identity.current.account_id}"
  
  tags = {
    Purpose            = "SBOM Storage"
    DataClassification = "Internal"
    Format             = "SPDX, CycloneDX"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "sbom_lifecycle" {
  bucket = aws_s3_bucket.sbom_storage.id
  
  rule {
    id     = "sbom_retention"
    status = "Enabled"
    
    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }
    
    transition {
      days          = 365
      storage_class = "GLACIER"
    }
    
    expiration {
      days = 2555  # 7 years retention
    }
    
    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
}

# サプライチェーン監視ダッシュボード用 Lambda
resource "aws_lambda_function" "supply_chain_monitor" {
  filename      = "supply_chain_monitor.zip"
  function_name = "supply-chain-security-monitor"
  role          = aws_iam_role.supply_chain_monitor_role.arn
  handler       = "index.handler"
  runtime       = "python3.9"
  timeout       = 300
  
  environment {
    variables = {
      VENDOR_TABLE          = aws_dynamodb_table.vendor_assessments.name
      DEPENDENCY_TABLE      = aws_dynamodb_table.dependency_scan_results.name
      CLOUDWATCH_NAMESPACE  = "SupplyChainSecurity"
      RISK_THRESHOLDS = jsonencode({
        critical = 0
        high     = 5
        medium   = 20
        low      = 50
      })
    }
  }
  
  tags = {
    Purpose = "Supply Chain Risk Monitoring"
  }
}

# ベンダーセキュリティ要件チェックリスト
resource "aws_ssm_parameter" "vendor_security_checklist" {
  name  = "/vendor/security/checklist"
  type  = "String"
  value = jsonencode({
    security_certifications = [
      "ISO 27001",
      "SOC 2 Type II",
      "CSA STAR"
    ]
    technical_controls = [
      "Encryption at rest and in transit",
      "Multi-factor authentication",
      "Regular security assessments",
      "Incident response plan",
      "Data backup and recovery"
    ]
    compliance_requirements = [
      "GDPR compliance",
      "Data residency options",
      "Right to audit clause",
      "Breach notification SLA",
      "Cyber insurance coverage"
    ]
    assessment_frequency = "Annual"
    risk_rating_matrix = {
      critical_vendor = "Quarterly assessment"
      high_risk = "Semi-annual assessment"
      medium_risk = "Annual assessment"
      low_risk = "Biennial assessment"
    }
  })
  
  tags = {
    Purpose = "Vendor Security Standards"
    LastUpdated = "2024-01-01"
  }
}
```

## 19. プライバシー・データ保護

### 実装対象サービス

**Amazon Macie（個人情報自動検出）**
- S3バケット内の個人情報を自動検出し、意図しない露出を防ぎます。機械学習により、構造化・非構造化データから個人情報を高精度で検出し、データ漏洩のリスクを最小化します。
- データ分類の自動化により、適切な保護レベルを適用します。検出されたデータの種類に応じて、自動的にタグ付けとアクセス制御を適用し、規制要件への準拠を確実にします。

**AWS KMS（暗号化キー管理）**
- データ分類に応じた暗号化キーの使い分けで、アクセス制御を強化します。機密データ、内部データ、公開データそれぞれに専用のKMSキーを使用し、きめ細かいアクセス制御を実現します。
- 自動キーローテーションにより、長期的な暗号化の安全性を保証します。年次でのキーローテーションを自動化し、古いキーの無効化も管理することで、暗号化の強度を維持します。

**Amazon S3（データローカライゼーション）**
- 地域別のデータ保存により、データ主権要件に対応します。日本、EU、米国など、各地域の規制に準拠したデータ保存を実現し、クロスボーダーのデータ転送リスクを排除します。
- レプリケーション制御により、意図しないデータ移動を防止します。特定地域のデータが他地域に複製されることを技術的に防止し、規制違反を回避します。

**AWS CloudTrail（データアクセス監査）**
- 個人データへのアクセスを完全に記録し、不正アクセスを検出します。誰が、いつ、どのデータにアクセスしたかを追跡し、データ主体からの開示請求にも迅速に対応できます。
- 異常なアクセスパターンの検出により、データ漏洩を早期発見します。大量ダウンロードや通常と異なるアクセスパターンを検出し、被害を最小限に抑えます。

**AWS Config（プライバシー設定監視）**
- プライバシー関連の設定を継続的に監視し、ポリシー違反を防止します。暗号化の無効化、アクセス制御の緩和などを即座に検出し、修正します。
- 自動修復により、プライバシー設定の一貫性を維持します。設定のドリフトを自動的に修正し、常に高いプライバシー保護レベルを維持します。

### Terraform実装コード

```hcl
# Amazon Macie 有効化（個人情報検出）
resource "aws_macie2_account" "main" {
  finding_publishing_frequency = "FIFTEEN_MINUTES"
  status                      = "ENABLED"
}

# Macie カスタムデータ識別子
resource "aws_macie2_custom_data_identifier" "japan_personal_info" {
  name        = "japan-personal-information"
  description = "Japanese personal information patterns"
  regex       = "(\\d{3}-\\d{4}-\\d{4})|([０-９]{3}-[０-９]{4}-[０-９]{4})"  # Japanese phone number
  
  keywords = [
    "氏名",
    "住所",
    "電話番号",
    "マイナンバー",
    "運転免許証"
  ]
  
  maximum_match_distance = 50
  
  tags = {
    DataType = "JapanesePersonalInfo"
    Compliance = "APPI"
  }
}

# Macie カスタム分類ジョブ
resource "aws_macie2_classification_job" "pii_discovery" {
  job_type = "SCHEDULED"
  name     = "pii-discovery-job"
  
  s3_job_definition {
    bucket_definitions {
      account_id = data.aws_caller_identity.current.account_id
      buckets    = [
        aws_s3_bucket.customer_data.arn,
        aws_s3_bucket.employee_data.arn,
        aws_s3_bucket.application_data.arn
      ]
    }
    
    scoping {
      excludes {
        and {
          simple_scope_term {
            comparator = "STARTS_WITH"
            key        = "OBJECT_KEY"
            values     = ["logs/", "temp/", ".git/"]
          }
        }
      }
      
      includes {
        and {
          simple_scope_term {
            comparator = "ENDS_WITH"
            key        = "OBJECT_EXTENSION"
            values     = [".csv", ".json", ".xlsx", ".pdf", ".txt"]
          }
        }
      }
    }
  }
  
  custom_data_identifier_ids = [
    aws_macie2_custom_data_identifier.japan_personal_info.id
  ]
  
  schedule_frequency = {
    daily_schedule = {}
  }
  
  tags = {
    Purpose = "PII Discovery and Classification"
    Frequency = "Daily"
  }
}

# 地域別データ分離用 S3 バケット（日本）
resource "aws_s3_bucket" "japan_data" {
  bucket = "technova-japan-data-${data.aws_caller_identity.current.account_id}"
  
  tags = {
    DataResidency = "Japan"
    Jurisdiction  = "Japan"
    GDPRScope     = "false"
    Purpose       = "Japan Personal Data Storage"
  }
}

resource "aws_s3_bucket_location_constraint" "japan_only" {
  bucket = aws_s3_bucket.japan_data.id
  
  rule {
    location_constraint = "ap-northeast-1"
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
      },
      {
        Sid       = "RequireEncryption"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.japan_data.arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      }
    ]
  })
}

# EU データ用 S3 バケット（GDPR対応）
resource "aws_s3_bucket" "eu_data" {
  provider = aws.eu_west_1
  bucket   = "technova-eu-data-${data.aws_caller_identity.current.account_id}"
  
  tags = {
    DataResidency = "EU"
    Jurisdiction  = "EU"
    GDPRScope     = "true"
    Purpose       = "EU Personal Data Storage"
    LegalBasis    = "Consent, Contract, Legitimate Interest"
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
      US_DATA_BUCKET       = aws_s3_bucket.us_data.id
      MACIE_FINDINGS_TABLE = aws_dynamodb_table.macie_findings.name
      DATA_CATALOG_TABLE   = aws_dynamodb_table.data_catalog.name
      RESPONSE_DEADLINE    = "30"  # days
      REQUEST_TYPES = jsonencode([
        "ACCESS",
        "RECTIFICATION", 
        "ERASURE",
        "PORTABILITY",
        "RESTRICTION",
        "OBJECTION"
      ])
    }
  }
  
  vpc_config {
    subnet_ids         = var.private_subnet_ids
    security_group_ids = [aws_security_group.lambda_sg.id]
  }
  
  tags = {
    Purpose = "GDPR Compliance Automation"
    DataProtection = "Required"
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
  
  attribute {
    name = "legal_basis"
    type = "S"
  }
  
  global_secondary_index {
    name            = "DataTypeIndex"
    hash_key        = "data_type"
    range_key       = "retention_date"
    projection_type = "ALL"
  }
  
  global_secondary_index {
    name            = "LegalBasisIndex"
    hash_key        = "legal_basis"
    range_key       = "data_subject_id"
    projection_type = "ALL"
  }
  
  ttl {
    attribute_name = "expiry_timestamp"
    enabled        = true
  }
  
  point_in_time_recovery {
    enabled = true
  }
  
  tags = {
    Purpose         = "Personal Data Inventory"
    GDPRCompliance = "Required"
    DataRetention  = "As per legal requirements"
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
      ERASURE_METHODS = jsonencode({
        immediate = "Direct deletion"
        crypto_shredding = "Delete encryption keys"
        anonymization = "Remove identifying information"
      })
      LEGAL_HOLD_CHECK = "ENABLED"
    }
  }
  
  dead_letter_config {
    target_arn = aws_sqs_queue.erasure_dlq.arn
  }
  
  tags = {
    Purpose = "GDPR Right to Erasure"
    Automation = "Partial"
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
  memory_size   = 2048
  
  environment {
    variables = {
      DATA_CATALOG_TABLE = aws_dynamodb_table.data_catalog.name
      EXPORT_BUCKET      = aws_s3_bucket.data_export.id
      ENCRYPTION_KEY     = aws_kms_key.gdpr_key.arn
      EXPORT_FORMATS     = jsonencode(["JSON", "CSV", "XML"])
      MAX_EXPORT_SIZE    = "5GB"
      DELIVERY_METHODS   = jsonencode(["S3_PRESIGNED_URL", "EMAIL_ENCRYPTED"])
    }
  }
  
  tags = {
    Purpose = "GDPR Data Portability"
    ExportCapability = "Machine-readable formats"
  }
}

# プライバシー影響評価（PIA）管理
resource "aws_dynamodb_table" "privacy_impact_assessments" {
  name         = "privacy-impact-assessments"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "assessment_id"
  range_key    = "version"
  
  attribute {
    name = "assessment_id"
    type = "S"
  }
  
  attribute {
    name = "version"
    type = "N"
  }
  
  attribute {
    name = "project_name"
    type = "S"
  }
  
  attribute {
    name = "risk_level"
    type = "S"
  }
  
  global_secondary_index {
    name            = "ProjectIndex"
    hash_key        = "project_name"
    range_key       = "version"
    projection_type = "ALL"
  }
  
  global_secondary_index {
    name            = "RiskIndex"
    hash_key        = "risk_level"
    range_key       = "assessment_id"
    projection_type = "ALL"
  }
  
  tags = {
    Purpose = "Privacy Impact Assessment Management"
    Compliance = "GDPR Article 35"
  }
}

# GDPR 監査ログ用 CloudWatch Log Group
resource "aws_cloudwatch_log_group" "gdpr_operations" {
  name              = "/aws/gdpr/operations"
  retention_in_days = 2555  # 7 years
  kms_key_id        = aws_kms_key.gdpr_key.arn
  
  tags = {
    Purpose = "GDPR Operations Audit Log"
    DataClassification = "Confidential"
  }
}

# データ暗号化キー（地域別）
resource "aws_kms_key" "regional_data_keys" {
  for_each = {
    japan = "ap-northeast-1"
    eu    = "eu-west-1"
    us    = "us-east-1"
  }
  
  description              = "Data encryption key for ${each.key} region"
  deletion_window_in_days  = 30
  enable_key_rotation      = true
  multi_region            = false  # データローカライゼーションのため
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow data services to use the key"
        Effect = "Allow"
        Principal = {
          Service = [
            "s3.amazonaws.com",
            "dynamodb.amazonaws.com",
            "macie.amazonaws.com"
          ]
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService" = "${each.value}.amazonaws.com"
          }
        }
      }
    ]
  })
  
  tags = {
    Region = each.key
    Purpose = "Regional Data Encryption"
    DataResidency = "Enforced"
  }
}

# 同意管理システム
resource "aws_dynamodb_table" "consent_management" {
  name         = "gdpr-consent-management"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "data_subject_id"
  range_key    = "consent_id"
  
  attribute {
    name = "data_subject_id"
    type = "S"
  }
  
  attribute {
    name = "consent_id"
    type = "S"
  }
  
  attribute {
    name = "purpose"
    type = "S"
  }
  
  attribute {
    name = "status"
    type = "S"
  }
  
  global_secondary_index {
    name            = "PurposeIndex"
    hash_key        = "purpose"
    range_key       = "status"
    projection_type = "ALL"
  }
  
  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"
  
  tags = {
    Purpose = "GDPR Consent Management"
    LegalRequirement = "Article 7"
  }
}
```

## 20. セキュリティコスト最適化

### 実装対象サービス

**AWS Cost Explorer（セキュリティコスト分析）**
- セキュリティサービスごとのコスト内訳を可視化し、ROIを測定します。GuardDuty、Security Hub、Macieなどのサービス別コストを追跡し、投資効果を定量的に評価することで、経営層への報告を効率化します。
- 未使用のセキュリティリソースを特定し、コスト削減機会を発見します。例えば、使用されていないWAFルールや、過剰なログ保存期間を特定し、年間数百万円のコスト削減を実現します。

**AWS Budgets（セキュリティ予算管理）**
- セキュリティ予算の80%到達時と予測超過時にアラートを発報します。早期の警告により、予算超過を未然に防ぎ、計画的なセキュリティ投資を可能にします。
- 部門別、サービス別の予算管理により、コスト意識を醸成します。各部門のセキュリティコストを可視化し、責任を明確化することで、無駄な支出を削減します。

**AWS Trusted Advisor（コスト最適化推奨）**
- セキュリティ設定の最適化提案により、過剰な保護を見直します。リスクレベルに応じた適切な保護レベルを維持しながら、コストを最適化します。
- 自動化可能な推奨事項を特定し、運用コストを削減します。手動作業を自動化することで、人件費を削減しながらセキュリティレベルを向上させます。

**Amazon CloudWatch（リソース使用率監視）**
- セキュリティリソースの使用率を監視し、適正サイジングを実現します。過剰にプロビジョニングされたリソースを特定し、コスト削減機会を創出します。
- 使用パターンの分析により、予約購入の機会を特定します。安定的に使用されるリソースについて、リザーブドインスタンスや Savings Plans の活用により、大幅なコスト削減を実現します。

**AWS Lambda（自動コスト最適化）**
- 未使用リソースの自動削除により、無駄なコストを排除します。開発環境の夜間停止、週末のリソース削減など、自動化により年間20-30%のコスト削減を実現します。
- コスト異常の自動検出により、予期しない支出を防止します。通常と異なる使用パターンを検出し、不正使用や設定ミスによる過剰請求を防ぎます。

### Terraform実装コード

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
      "AWS Key Management Service",
      "AWS WAF",
      "AWS Shield",
      "Amazon Detective"
    ]
  }
  
  cost_types {
    include_credit             = false
    include_discount           = true
    include_other_subscription = true
    include_recurring          = true
    include_refund            = false
    include_subscription      = true
    include_support           = false
    include_tax               = true
    include_upfront           = true
    use_amortized             = false
    use_blended               = false
  }
  
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                 = 80
    threshold_type            = "PERCENTAGE"
    notification_type         = "ACTUAL"
    subscriber_email_addresses = ["security-team@technova.com", "finance@technova.com"]
    subscriber_sns_topic_arns  = [aws_sns_topic.budget_alerts.arn]
  }
  
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                 = 100
    threshold_type            = "PERCENTAGE"
    notification_type         = "FORECASTED"
    subscriber_email_addresses = ["ciso@technova.com", "cfo@technova.com"]
    subscriber_sns_topic_arns  = [aws_sns_topic.budget_critical_alerts.arn]
  }
  
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                 = 120
    threshold_type            = "PERCENTAGE"
    notification_type         = "ACTUAL"
    subscriber_email_addresses = ["ceo@technova.com"]
  }
}

# 部門別セキュリティ予算
resource "aws_budgets_budget" "department_security_budgets" {
  for_each = {
    engineering = 3000
    sales       = 1000
    operations  = 2000
    hr          = 500
  }
  
  name         = "security-budget-${each.key}"
  budget_type  = "COST"
  limit_amount = each.value
  limit_unit   = "USD"
  time_unit    = "MONTHLY"
  
  cost_filters = {
    TagKeyValue = ["Department${each.key}"]
  }
  
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                 = 90
    threshold_type            = "PERCENTAGE"
    notification_type         = "ACTUAL"
    subscriber_email_addresses = ["${each.key}-manager@technova.com"]
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
      COST_EXPLORER_REGION  = "us-east-1"  # Cost Explorer API endpoint
      SECURITY_SERVICES     = jsonencode([
        "GuardDuty",
        "SecurityHub", 
        "Macie",
        "Inspector",
        "Config",
        "CloudTrail",
        "KMS",
        "WAF",
        "Shield"
      ])
      UTILIZATION_THRESHOLD = "70"
      REPORT_BUCKET         = aws_s3_bucket.cost_reports.id
      ANALYSIS_CONFIG = jsonencode({
        lookback_days = 90
        forecast_days = 30
        granularity  = "DAILY"
        metrics      = ["BlendedCost", "UnblendedCost", "UsageQuantity"]
      })
    }
  }
  
  tags = {
    Purpose = "Security Cost Optimization"
    Schedule = "Weekly"
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
  
  attribute {
    name = "implementation_effort"
    type = "S"
  }
  
  global_secondary_index {
    name            = "SavingsIndex"
    hash_key        = "potential_savings"
    range_key       = "recommendation_date"
    projection_type = "ALL"
  }
  
  global_secondary_index {
    name            = "EffortIndex"
    hash_key        = "implementation_effort"
    range_key       = "potential_savings"
    projection_type = "ALL"
  }
  
  tags = {
    Purpose = "Cost Optimization Tracking"
    ReviewCycle = "Monthly"
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
      AUTO_CLEANUP_ENABLED  = "false"  # Manual approval required
      NOTIFICATION_TOPIC    = aws_sns_topic.cost_optimization_alerts.arn
      RESOURCE_TYPES = jsonencode({
        waf_rules = {
          threshold_days = 60
          auto_disable   = true
        }
        config_rules = {
          threshold_days = 90
          auto_disable   = false
        }
        cloudtrail_trails = {
          threshold_days = 180
          auto_disable   = false
        }
        guardduty_filters = {
          threshold_days = 30
          auto_disable   = true
        }
      })
    }
  }
  
  tags = {
    Purpose = "Resource Optimization"
    Risk = "Medium"
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
            [ "SecurityMetrics", "ThreatsPrevented", { stat = "Sum", label = "Threats Prevented" } ],
            [ ".", "SecurityIncidents", { stat = "Sum", label = "Security Incidents" } ],
            [ ".", "ComplianceViolations", { stat = "Sum", label = "Compliance Violations" } ]
          ]
          period = 2592000  # 30 days
          stat   = "Sum"
          region = var.aws_region
          title  = "Security Effectiveness Metrics"
          yAxis = {
            left = {
              label = "Count"
              showUnits = false
            }
          }
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        
        properties = {
          metrics = [
            [ "AWS/Billing", "EstimatedCharges", "Currency", "USD", "ServiceName", "AmazonGuardDuty" ],
            [ "...", "AWSSecurityHub" ],
            [ "...", "AmazonMacie" ],
            [ "...", "AmazonInspector" ],
            [ "...", "AWSConfig" ]
          ]
          period = 86400
          stat   = "Maximum"
          region = "us-east-1"
          title  = "Security Services Cost Trend"
          yAxis = {
            left = {
              label = "Cost (USD)"
              showUnits = false
            }
          }
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 24
        height = 6
        
        properties = {
          metrics = [
            [ { expression = "m1/m2*100", label = "ROI %", id = "e1" } ],
            [ "SecurityMetrics", "SecurityValue", { id = "m1", visible = false } ],
            [ "AWS/Billing", "EstimatedCharges", { id = "m2", visible = false } ]
          ]
          period = 2592000
          stat   = "Average"
          region = var.aws_region
          title  = "Security ROI Percentage"
          yAxis = {
            left = {
              label = "ROI %"
              showUnits = false
            }
          }
        }
      }
    ]
  })
}

# コスト異常検知設定
resource "aws_ce_anomaly_monitor" "security_costs" {
  name              = "security-services-cost-anomaly"
  monitor_type      = "CUSTOM"
  monitor_frequency = "DAILY"
  
  monitor_specification = jsonencode({
    Service = {
      Key          = "SERVICE"
      Values       = ["Amazon GuardDuty", "AWS Security Hub", "Amazon Macie"]
      MatchOptions = ["EQUALS"]
    }
  })
}

resource "aws_ce_anomaly_subscription" "security_alerts" {
  name      = "security-cost-anomaly-alerts"
  threshold = 100.0
  frequency = "IMMEDIATE"
  
  monitor_arn_list = [
    aws_ce_anomaly_monitor.security_costs.arn
  ]
  
  subscriber {
    type    = "EMAIL"
    address = "security-finance@technova.com"
  }
  
  subscriber {
    type    = "SNS"
    address = aws_sns_topic.cost_anomaly_alerts.arn
  }
}

# セキュリティコスト配分タグ
resource "aws_organizations_policy" "security_tagging" {
  name        = "security-cost-allocation-tags"
  description = "Enforce security cost allocation tagging"
  type        = "TAG_POLICY"
  
  content = jsonencode({
    tags = {
      SecurityService = {
        tag_key = "SecurityService"
        tag_value = {
          "@@assign" = [
            "GuardDuty",
            "SecurityHub",
            "Macie",
            "Inspector",
            "Config",
            "CloudTrail",
            "WAF",
            "Shield"
          ]
        }
        enforced_for = [
          "ec2:instance",
          "s3:bucket",
          "lambda:function"
        ]
      }
      CostCenter = {
        tag_key = "CostCenter"
        tag_value = {
          "@@assign" = ["Security", "Engineering", "Operations"]
        }
        enforced_for = ["*"]
      }
    }
  })
}
```

## 21. 継続的改善・成熟度向上

### 実装対象サービス

**AWS Well-Architected Tool（セキュリティ評価）**
- 四半期ごとにセキュリティピラーの評価を実施し、改善点を特定します。AWSのベストプラクティスに基づく客観的な評価により、組織のセキュリティ成熟度を定量的に把握し、改善の優先順位を明確化します。
- 業界ベストプラクティスとのギャップ分析により、改善優先順位を決定します。同業他社との比較により、競争優位性を維持しながら、効率的な改善活動を実施します。

**AWS Systems Manager（運用成熟度管理）**
- セキュリティ運用の標準化と自動化により、属人性を排除します。運用手順書をコード化し、誰でも同じ品質で運用できる体制を構築することで、人的エラーを最小化します。
- 運用手順書の一元管理により、インシデント対応の品質を向上させます。最新の手順書が常に利用可能な状態を維持し、迅速かつ的確な対応を可能にします。

**Amazon QuickSight（セキュリティメトリクス可視化）**
- セキュリティKPIの可視化により、改善効果を定量的に把握します。MTTD、MTTR、コンプライアンススコアなどの重要指標をダッシュボードで一元管理し、経営層への報告を効率化します。
- トレンド分析により、将来の脅威を予測します。過去のインシデントデータから傾向を分析し、予防的な対策を実施することで、インシデントの発生を未然に防ぎます。

**AWS Config（設定管理成熟度）**
- 設定の一貫性を継続的に監視し、ドリフトを防止します。承認された設定からの逸脱を即座に検出し、自動修復することで、常に安全な状態を維持します。
- コンプライアンススコアの向上により、監査対応を効率化します。常時99.5%以上のコンプライアンススコアを維持することで、監査時の指摘事項を最小化します。

**AWS Lambda（成熟度評価自動化）**
- 成熟度評価の自動化により、客観的な評価を実現します。人的バイアスを排除し、一貫性のある評価基準により、正確な成熟度レベルを把握します。
- 改善提案の自動生成により、効率的な改善活動を支援します。評価結果に基づいて、具体的な改善アクションを自動的に提案し、PDCAサイクルを加速します。

### Terraform実装コード

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
  
  attribute {
    name = "framework"
    type = "S"
  }
  
  global_secondary_index {
    name            = "MaturityLevelIndex"
    hash_key        = "maturity_level"
    range_key       = "assessment_date"
    projection_type = "ALL"
  }
  
  global_secondary_index {
    name            = "FrameworkIndex"
    hash_key        = "framework"
    range_key       = "maturity_level"
    projection_type = "ALL"
  }
  
  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"
  
  tags = {
    Purpose = "Security Maturity Tracking"
    Frameworks = "NIST-CSF, ISO27001, CIS"
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
  
  layers = [
    "arn:aws:lambda:${var.aws_region}:336392948345:layer:AWSSDKPandas-Python39:1"
  ]
  
  environment {
    variables = {
      SECURITY_HUB_REGION   = var.aws_region
      GUARDDUTY_DETECTOR_ID = aws_guardduty_detector.main.id
      CONFIG_RECORDER_NAME  = aws_config_configuration_recorder.recorder.name
      MATURITY_TABLE        = aws_dynamodb_table.security_maturity_assessments.name
      CLOUDWATCH_NAMESPACE  = "TechNova/SecurityMaturity"
      METRICS_CONFIG = jsonencode({
        dimensions = {
          nist_csf = ["Identify", "Protect", "Detect", "Respond", "Recover"]
          iso27001 = ["A5", "A6", "A7", "A8", "A9", "A10", "A11", "A12", "A13", "A14"]
          cis      = ["IG1", "IG2", "IG3"]
        }
        scoring_weights = {
          automated_controls   = 0.4
          documented_process  = 0.2
          regular_testing     = 0.2
          continuous_improvement = 0.2
        }
      })
    }
  }
  
  vpc_config {
    subnet_ids         = var.private_subnet_ids
    security_group_ids = [aws_security_group.lambda_sg.id]
  }
  
  tags = {
    Purpose = "Security Maturity Measurement"
    DataSources = "Multiple"
  }
}

# セキュリティベンチマーク用 Systems Manager パラメータ
resource "aws_ssm_parameter" "security_benchmarks" {
  name = "/security/benchmarks/current"
  type = "String"
  tier = "Advanced"  # For larger parameter size
  
  value = jsonencode({
    operational_metrics = {
      detection_time_target        = 300     # 5 minutes
      containment_time_target      = 1800    # 30 minutes
      recovery_time_target         = 14400   # 4 hours
      false_positive_threshold     = 5       # 5%
      automation_target           = 80       # 80% automated response
    }
    compliance_metrics = {
      overall_score_target        = 99.5     # 99.5%
      critical_controls_target    = 100      # 100%
      high_controls_target        = 98       # 98%
      audit_readiness_target      = 95       # 95%
    }
    vulnerability_metrics = {
      scan_coverage_target        = 100      # 100%
      remediation_sla = {
        critical = 2880   # 48 hours in minutes
        high     = 10080  # 7 days in minutes
        medium   = 43200  # 30 days in minutes
        low      = 129600 # 90 days in minutes
      }
    }
    training_metrics = {
      completion_rate_target      = 100      # 100%
      phishing_resilience_target  = 95       # 95% report rate
      certification_target        = 90       # 90% certified
    }
    maturity_targets = {
      year_1 = 3.0  # Defined
      year_2 = 3.5  # Managed
      year_3 = 4.0  # Quantitatively Managed
      year_5 = 4.5  # Optimizing
    }
  })
  
  tags = {
    Purpose = "Security Performance Benchmarks"
    ReviewCycle = "Quarterly"
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
        Parameters = {
          "cycle_id.$" = "$.Execution.Name"
          "phase" = "Act"
          "assessment.$" = "$.check_output"
          "improvement_actions" = [
            "Update Standards",
            "Optimize Processes",
            "Adjust Controls",
            "Document Lessons"
          ]
        }
        End = true
      }
      HandleError = {
        Type = "Task"
        Resource = aws_lambda_function.pdca_error_handler.arn
        End = true
      }
    }
  })
  
  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.step_functions.arn}:*"
    include_execution_data = true
    level                  = "ALL"
  }
  
  tags = {
    Purpose = "Security Continuous Improvement"
    Frequency = "Quarterly"
  }
}

# セキュリティKPI可視化用 QuickSight データセット
resource "aws_quicksight_data_source" "security_metrics" {
  data_source_id = "security-metrics-source"
  name           = "Security Metrics Data Source"
  
  parameters {
    athena {
      work_group = aws_athena_workgroup.security_analytics.name
    }
  }
  
  type = "ATHENA"
  
  permission {
    principal = aws_quicksight_group.security_analysts.arn
    actions   = ["quicksight:DescribeDataSource", "quicksight:DescribeDataSourcePermissions", "quicksight:PassDataSource"]
  }
}

resource "aws_quicksight_data_set" "security_kpis" {
  data_set_id = "security-kpis-dataset"
  name        = "Security KPIs Dataset"
  import_mode = "SPICE"
  
  physical_table_map {
    physical_table_map_id = "security-metrics-table"
    
    s3_source {
      data_source_arn = aws_quicksight_data_source.security_metrics.arn
      
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
        name = "dimension"
        type = "STRING"
      }
      
      input_columns {
        name = "target_value"
        type = "DECIMAL"
      }
      
      upload_settings {
        format = "JSON"
      }
    }
  }
  
  logical_table_map {
    logical_table_map_id = "security-kpis-logical"
    alias               = "Security KPIs"
    
    source {
      physical_table_id = "security-metrics-table"
    }
    
    data_transforms {
      cast_column_type_operation {
        column_name = "timestamp"
        new_column_type = "DATETIME"
      }
    }
    
    data_transforms {
      create_columns_operation {
        columns {
          column_id   = "achievement_rate"
          column_name = "Achievement Rate"
          expression  = "{metric_value} / {target_value} * 100"
        }
      }
    }
  }
  
  row_level_permission_data_set {
    arn = aws_quicksight_data_set.security_permissions.arn
    permission_policy = "GRANT_ACCESS"
  }
  
  tags = {
    Purpose = "Security KPI Visualization"
    RefreshFrequency = "Daily"
  }
}

# セキュリティ成熟度レポート生成用 EventBridge スケジュール
resource "aws_cloudwatch_event_rule" "monthly_maturity_assessment" {
  name                = "monthly-security-maturity-assessment"
  description         = "Monthly security maturity assessment"
  schedule_expression = "cron(0 9 1 * ? *)"  # 毎月1日 9:00 JST
  
  tags = {
    Purpose = "Automated Assessment"
  }
}

resource "aws_cloudwatch_event_target" "maturity_assessment_target" {
  rule      = aws_cloudwatch_event_rule.monthly_maturity_assessment.name
  target_id = "MaturityAssessmentLambda"
  arn       = aws_lambda_function.security_metrics_aggregator.arn
  
  input_transformer {
    input_paths = {
      time = "$.time"
    }
    input_template = jsonencode({
      assessment_type = "monthly_maturity"
      frameworks     = ["NIST-CSF", "ISO27001", "CIS"]
      report_format  = "executive_summary"
      distribution   = ["CISO", "Security Team", "Auditors"]
    })
  }
}

# 改善アクション追跡
resource "aws_dynamodb_table" "improvement_actions" {
  name         = "security-improvement-actions"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "action_id"
  range_key    = "created_date"
  
  attribute {
    name = "action_id"
    type = "S"
  }
  
  attribute {
    name = "created_date"
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
  
  ttl {
    attribute_name = "expiry_time"
    enabled        = true
  }
  
  tags = {
    Purpose = "Improvement Action Tracking"
    Process = "PDCA"
  }
}
```

## 22. セキュリティ実装ロードマップ

### 実装対象サービス

**AWS Systems Manager（実装進捗管理）**
- 実装タスクの一元管理により、進捗を可視化します。各フェーズのタスク、依存関係、完了状況を管理し、プロジェクト全体の進捗を正確に把握します。
- 自動化されたステータス更新により、リアルタイムな進捗管理を実現します。各タスクの完了を自動的に検知し、ダッシュボードに反映することで、手動更新の手間を削減します。

**AWS CodePipeline（段階的デプロイメント）**
- 段階的なセキュリティ機能の展開により、リスクを最小化します。開発環境から本番環境への段階的な展開により、問題を早期に発見し、影響範囲を限定します。
- 自動化されたテストとロールバックにより、品質を保証します。各段階でのセキュリティテストを自動実行し、問題検出時は自動的にロールバックすることで、安全な展開を実現します。

**Amazon EventBridge（フェーズ管理）**
- フェーズ間の自動移行により、プロジェクトを効率的に進行させます。前フェーズの完了を自動的に検知し、次フェーズを開始することで、プロジェクトの停滞を防ぎます。
- マイルストーン達成の自動通知により、ステークホルダーへの報告を効率化します。重要な達成事項を自動的に通知し、プロジェクトの透明性を確保します。

**AWS Lambda（実装自動化）**
- インフラのコード化により、一貫性のある実装を実現します。Terraformによるインフラ定義により、環境間の差異を排除し、予測可能な結果を得られます。
- 自動化されたセキュリティ設定により、人的ミスを防止します。ベストプラクティスに基づいた設定を自動適用し、セキュリティホールの発生を防ぎます。

**Amazon CloudWatch（実装監視）**
- 実装状況のリアルタイム監視により、問題を早期発見します。エラー率、成功率、処理時間などのメトリクスを監視し、異常を即座に検出します。
- KPIダッシュボードにより、目標達成状況を可視化します。各フェーズの成功基準に対する達成度を一目で把握し、必要な対策を迅速に実施できます。

### Terraform実装コード

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
  
  attribute {
    name = "assigned_team"
    type = "S"
  }
  
  global_secondary_index {
    name            = "StatusIndex"
    hash_key        = "status"
    range_key       = "priority"
    projection_type = "ALL"
  }
  
  global_secondary_index {
    name            = "TeamIndex"
    hash_key        = "assigned_team"
    range_key       = "status"
    projection_type = "ALL"
  }
  
  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"
  
  tags = {
    Purpose = "Implementation Progress Tracking"
    ProjectPhase = "Security Enhancement 2024"
  }
}

# フェーズ定義
resource "aws_ssm_parameter" "implementation_phases" {
  name = "/security/implementation/phases"
  type = "String"
  tier = "Advanced"
  
  value = jsonencode({
    phases = [
      {
        id = "phase1_foundation"
        name = "Security Foundation"
        duration = "3 months"
        objectives = [
          "Establish centralized logging",
          "Implement IAM baseline",
          "Deploy core security services",
          "Set up monitoring dashboard"
        ]
        success_criteria = {
          logging_coverage = 100
          iam_compliance = 95
          service_deployment = 100
          dashboard_availability = 99.9
        }
      },
      {
        id = "phase2_detection"
        name = "Threat Detection Enhancement"
        duration = "2 months"
        objectives = [
          "Deploy GuardDuty across all accounts",
          "Implement custom threat intelligence",
          "Set up automated response",
          "Create incident playbooks"
        ]
        dependencies = ["phase1_foundation"]
      },
      {
        id = "phase3_compliance"
        name = "Compliance Automation"
        duration = "3 months"
        objectives = [
          "Implement Config rules",
          "Deploy conformance packs",
          "Automate compliance reporting",
          "Set up continuous auditing"
        ]
        dependencies = ["phase1_foundation", "phase2_detection"]
      },
      {
        id = "phase4_optimization"
        name = "Cost and Performance Optimization"
        duration = "2 months"
        objectives = [
          "Implement cost monitoring",
          "Optimize security configurations",
          "Automate resource cleanup",
          "Establish KPI tracking"
        ]
        dependencies = ["phase3_compliance"]
      }
    ]
  })
  
  tags = {
    Purpose = "Implementation Planning"
    LastUpdated = "2024-01-01"
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
      provider         = "CodeCommit"
      version          = "1"
      output_artifacts = ["source_output"]
      
      configuration = {
        RepositoryName = aws_codecommit_repository.security_iac.repository_name
        BranchName     = "main"
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
      output_artifacts = ["validated_output"]
      
      configuration = {
        ProjectName = aws_codebuild_project.security_validation.name
      }
    }
  }
  
  stage {
    name = "TestEnvironment"
    
    action {
      name             = "DeployToTest"
      category         = "Build"
      owner            = "AWS"
      provider         = "CodeBuild"
      version          = "1"
      input_artifacts  = ["validated_output"]
      output_artifacts = ["test_output"]
      
      configuration = {
        ProjectName = aws_codebuild_project.deploy_test.name
      }
    }
    
    action {
      name             = "IntegrationTests"
      category         = "Test"
      owner            = "AWS"
      provider         = "CodeBuild"
      version          = "1"
      input_artifacts  = ["test_output"]
      
      configuration = {
        ProjectName = aws_codebuild_project.integration_tests.name
      }
    }
  }
  
  stage {
    name = "Approval"
    
    action {
      name     = "ManualApproval"
      category = "Approval"
      owner    = "AWS"
      provider = "Manual"
      version  = "1"
      
      configuration = {
        CustomData = "Please review test results and approve production deployment"
        NotificationArn = aws_sns_topic.deployment_approval.arn
      }
    }
  }
  
  stage {
    name = "Production"
    
    action {
      name             = "DeployToProduction"
      category         = "Build"
      owner            = "AWS"
      provider         = "CodeBuild"
      version          = "1"
      input_artifacts  = ["validated_output"]
      
      configuration = {
        ProjectName = aws_codebuild_project.deploy_production.name
      }
    }
  }
  
  tags = {
    Phase    = "Foundation"
    Priority = "Critical"
    RiskLevel = "High"
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
  memory_size   = 512
  
  environment {
    variables = {
      ROADMAP_TABLE         = aws_dynamodb_table.implementation_roadmap.name
      CODEPIPELINE_NAMES    = jsonencode([
        aws_codepipeline.phase1_foundation.name,
        "security-phase2-detection",
        "security-phase3-compliance",
        "security-phase4-optimization"
      ])
      SLACK_WEBHOOK_URL     = aws_ssm_parameter.slack_webhook.name
      SUCCESS_CRITERIA_TABLE = aws_dynamodb_table.success_criteria.name
      METRICS_NAMESPACE     = "SecurityImplementation"
      NOTIFICATION_CONFIG = jsonencode({
        channels = {
          slack = {
            enabled = true
            webhook_param = "/slack/security-implementation"
          }
          email = {
            enabled = true
            topic_arn = aws_sns_topic.implementation_updates.arn
          }
          teams = {
            enabled = false
            webhook_param = "/teams/security-implementation"
          }
        }
        escalation_thresholds = {
          task_delay_hours = 24
          phase_delay_days = 7
          budget_overrun_percent = 10
        }
      })
    }
  }
  
  tags = {
    Purpose = "Implementation Progress Monitoring"
    NotificationEnabled = "true"
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
  
  attribute {
    name = "measurement_type"
    type = "S"
  }
  
  global_secondary_index {
    name            = "AchievementIndex"
    hash_key        = "achievement_status"
    range_key       = "phase_id"
    projection_type = "ALL"
  }
  
  global_secondary_index {
    name            = "MeasurementTypeIndex"
    hash_key        = "measurement_type"
    range_key       = "achievement_status"
    projection_type = "ALL"
  }
  
  tags = {
    Purpose = "Success Criteria Tracking"
    Compliance = "Required for phase gates"
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
  memory_size   = 1024
  
  environment {
    variables = {
      SUCCESS_CRITERIA_TABLE = aws_dynamodb_table.success_criteria.name
      SECURITY_HUB_REGION    = var.aws_region
      COMPLIANCE_THRESHOLD   = "95"
      APPROVAL_SNS_TOPIC     = aws_sns_topic.phase_gate_approvals.arn
      VALIDATION_CHECKS = jsonencode({
        security_hub_score = {
          weight = 0.3
          threshold = 95
        }
        config_compliance = {
          weight = 0.3
          threshold = 98
        }
        vulnerability_remediation = {
          weight = 0.2
          threshold = 90
        }
        incident_metrics = {
          weight = 0.2
          threshold = 85
        }
      })
    }
  }
  
  tags = {
    Purpose = "Phase Gate Validation"
    CriticalPath = "true"
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
            [ "SecurityImplementation", "TasksCompleted", "Phase", "Foundation", { stat = "Sum" } ],
            [ ".", "TasksTotal", ".", ".", { stat = "Average" } ],
            [ ".", "TasksCompleted", ".", "Detection", { stat = "Sum" } ],
            [ ".", "TasksTotal", ".", ".", { stat = "Average" } ],
            [ ".", "TasksCompleted", ".", "Compliance", { stat = "Sum" } ],
            [ ".", "TasksTotal", ".", ".", { stat = "Average" } ]
          ]
          period = 86400
          stat   = "Average"
          region = var.aws_region
          title  = "Implementation Progress by Phase"
          yAxis = {
            left = {
              label = "Task Count"
              showUnits = false
            }
          }
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        
        properties = {
          metrics = [
            [ "AWS/CodePipeline", "PipelineExecutionSuccess", "PipelineName", aws_codepipeline.phase1_foundation.name ],
            [ ".", "PipelineExecutionFailure", ".", "." ],
            [ "AWS/CodeBuild", "SucceededBuilds", "ProjectName", aws_codebuild_project.deploy_production.name ],
            [ ".", "FailedBuilds", ".", "." ]
          ]
          period = 3600
          stat   = "Sum"
          region = var.aws_region
          title  = "Deployment Success Rate"
          yAxis = {
            left = {
              label = "Count"
              showUnits = false
            }
          }
        }
      },
      {
        type   = "log"
        x      = 0
        y      = 6
        width  = 24
        height = 6
        
        properties = {
          query  = <<-EOT
            SOURCE '/aws/lambda/security-implementation-monitor'
            | fields @timestamp, phase_id, completion_percentage, blocked_tasks
            | filter completion_percentage > 0
            | stats max(completion_percentage) as progress, count(blocked_tasks) as blockers by phase_id
            | sort phase_id desc
          EOT
          region = var.aws_region
          title  = "Phase Completion Progress"
        }
      },
      {
        type   = "number"
        x      = 0
        y      = 12
        width  = 6
        height = 3
        
        properties = {
          metrics = [
            [ "SecurityImplementation", "OverallProgress", { stat = "Average" } ]
          ]
          period = 86400
          stat   = "Average"
          region = var.aws_region
          title  = "Overall Progress %"
        }
      },
      {
        type   = "number"
        x      = 6
        y      = 12
        width  = 6
        height = 3
        
        properties = {
          metrics = [
            [ "SecurityImplementation", "DaysRemaining", { stat = "Minimum" } ]
          ]
          period = 86400
          stat   = "Minimum"
          region = var.aws_region
          title  = "Days to Completion"
        }
      },
      {
        type   = "number"
        x      = 12
        y      = 12
        width  = 6
        height = 3
        
        properties = {
          metrics = [
            [ "SecurityImplementation", "BudgetUtilization", { stat = "Average" } ]
          ]
          period = 86400
          stat   = "Average"
          region = var.aws_region
          title  = "Budget Utilization %"
        }
      },
      {
        type   = "number"
        x      = 18
        y      = 12
        width  = 6
        height = 3
        
        properties = {
          metrics = [
            [ "SecurityImplementation", "RiskScore", { stat = "Average" } ]
          ]
          period = 86400
          stat   = "Average"
          region = var.aws_region
          title  = "Implementation Risk Score"
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
      ROLLBACK_STRATEGIES = jsonencode({
        immediate = {
          approval_required = false
          backup_validation = true
          notification = "all"
        }
        scheduled = {
          approval_required = true
          maintenance_window = "required"
          notification = "stakeholders"
        }
        partial = {
          approval_required = true
          scope = "affected_resources_only"
          notification = "technical_team"
        }
      })
    }
  }
  
  dead_letter_config {
    target_arn = aws_sqs_queue.rollback_dlq.arn
  }
  
  tags = {
    Purpose = "Implementation Rollback Automation"
    RiskMitigation = "Critical"
  }
}

# 実装完了通知用 EventBridge ルール
resource "aws_cloudwatch_event_rule" "implementation_milestones" {
  name        = "security-implementation-milestones"
  description = "Security implementation milestone notifications"
  
  event_pattern = jsonencode({
    source      = ["custom.security.implementation"]
    detail-type = ["Phase Completion", "Milestone Achievement", "Critical Issue"]
    detail = {
      status = ["COMPLETED", "ACHIEVED", "BLOCKED"]
    }
  })
  
  tags = {
    Purpose = "Milestone Tracking"
  }
}

resource "aws_cloudwatch_event_target" "milestone_notification" {
  rule      = aws_cloudwatch_event_rule.implementation_milestones.name
  target_id = "MilestoneNotificationLambda"
  arn       = aws_lambda_function.milestone_notifier.arn
  
  input_transformer {
    input_paths = {
      phase     = "$.detail.phase"
      milestone = "$.detail.milestone"
      status    = "$.detail.status"
      impact    = "$.detail.impact"
    }
    input_template = jsonencode({
      notification_type = "milestone"
      phase            = "<phase>"
      milestone        = "<milestone>"
      status           = "<status>"
      impact           = "<impact>"
      recipients       = ["security-team", "project-management", "executive"]
    })
  }
}

# 実装リスク管理
resource "aws_dynamodb_table" "implementation_risks" {
  name         = "security-implementation-risks"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "risk_id"
  range_key    = "identified_date"
  
  attribute {
    name = "risk_id"
    type = "S"
  }
  
  attribute {
    name = "identified_date"
    type = "S"
  }
  
  attribute {
    name = "risk_level"
    type = "S"
  }
  
  attribute {
    name = "phase_id"
    type = "S"
  }
  
  global_secondary_index {
    name            = "RiskLevelIndex"
    hash_key        = "risk_level"
    range_key       = "phase_id"
    projection_type = "ALL"
  }
  
  global_secondary_index {
    name            = "PhaseRiskIndex"
    hash_key        = "phase_id"
    range_key       = "risk_level"
    projection_type = "ALL"
  }
  
  tags = {
    Purpose = "Implementation Risk Management"
    ReviewFrequency = "Weekly"
  }
}

# 週次ステータスレポート生成
resource "aws_lambda_function" "weekly_status_report" {
  filename      = "weekly_status_report.zip"
  function_name = "implementation-weekly-status"
  role          = aws_iam_role.reporting_role.arn
  handler       = "index.handler"
  runtime       = "python3.9"
  timeout       = 300
  
  environment {
    variables = {
      ROADMAP_TABLE     = aws_dynamodb_table.implementation_roadmap.name
      RISKS_TABLE       = aws_dynamodb_table.implementation_risks.name
      REPORT_BUCKET     = aws_s3_bucket.implementation_reports.id
      DISTRIBUTION_LIST = jsonencode([
        "security-team@technova.com",
        "project-management@technova.com",
        "ciso@technova.com"
      ])
      REPORT_TEMPLATE   = "s3://${aws_s3_bucket.report_templates.id}/weekly-status.html"
    }
  }
  
  tags = {
    Purpose = "Weekly Status Reporting"
    Automation = "Full"
  }
}

resource "aws_cloudwatch_event_rule" "weekly_report_schedule" {
  name                = "implementation-weekly-report"
  description         = "Generate weekly implementation status report"
  schedule_expression = "cron(0 9 ? * MON *)"  # Every Monday at 9:00 AM
  
  tags = {
    Purpose = "Automated Reporting"
  }
}

resource "aws_cloudwatch_event_target" "weekly_report_target" {
  rule      = aws_cloudwatch_event_rule.weekly_report_schedule.name
  target_id = "WeeklyReportLambda"
  arn       = aws_lambda_function.weekly_status_report.arn
}
```

## まとめ

この包括的なセキュリティ設計により、TechNova社は120アカウントのマルチアカウント環境において、以下を実現します：

### 主要サービス対応表

| **セクション** | **主要AWSサービス** | **具体的な設定内容** |
|:---|:---|:---|
| **セキュリティ運用・管理** | Security Hub, GuardDuty, CloudWatch | 統合セキュリティ監視、メトリクス収集、アラート設定により、組織全体のセキュリティ状況を一元管理 |
| **脅威対応** | GuardDuty, Lambda, S3, EventBridge | 脅威インテリジェンス統合、AI分析、自動対応により、未知の脅威にも迅速に対応 |
| **セキュリティ教育** | DynamoDB, SES, Lambda, CloudWatch | フィッシングシミュレーション、教育記録管理により、人的要因によるリスクを最小化 |
| **サプライチェーン** | Inspector, ECR, CodeBuild, Config | 脆弱性スキャン、セキュアビルド、SBOM管理により、サプライチェーン攻撃を防止 |
| **プライバシー保護** | Macie, KMS, S3, Lambda | 個人情報検出、暗号化、GDPR対応により、データ保護規制に完全準拠 |
| **コスト最適化** | Cost Explorer, Budgets, Lambda | セキュリティコスト監視、ROI分析により、効果的なセキュリティ投資を実現 |
| **継続的改善** | Systems Manager, QuickSight, Step Functions | 成熟度評価、PDCA自動化、KPI可視化により、セキュリティレベルを継続的に向上 |
| **実装管理** | CodePipeline, DynamoDB, EventBridge | 段階的実装、進捗監視、フェーズゲートにより、計画的なセキュリティ強化を実現 |

### 重要な設定ポイント

1. **自動化の実現**: Lambda関数による運用タスクの自動化により、人的ミスを削減し、24時間365日の監視体制を実現

2. **統合監視**: CloudWatchダッシュボードによる一元的な可視化により、複雑な環境でも効率的な管理を可能に

3. **コンプライアンス**: Config Rules、Security Hub標準による継続的監査により、常に高いコンプライアンスレベルを維持

4. **データ保護**: KMS暗号化、Macie個人情報検出の組み合わせにより、データ漏洩リスクを最小化

5. **コスト管理**: Budgets、Cost Explorerによる費用対効果の監視により、セキュリティ投資のROIを最大化

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

各セキュリティ機能は相互に連携し、多層防御を実現することで、単一の脆弱性が致命的な被害につながることを防ぎます。また、自動化と可視化により、限られたセキュリティ人材でも効果的な運用が可能となり、ビジネスの成長に合わせてスケールできる体制を構築します。

### 実装ロードマップの重要性

段階的な実装アプローチにより、リスクを管理しながら着実にセキュリティレベルを向上させます。各フェーズでの成功基準を明確に定義し、継続的なモニタリングとフィードバックループを確立することで、プロジェクトの成功を確実なものとします。

この包括的なセキュリティアーキテクチャは、TechNova社の現在のニーズに対応するだけでなく、将来の成長と変化にも柔軟に適応できる、真に企業価値を高めるセキュリティ基盤を提供します。 "Plan"
          "activities" = [
            "Risk Assessment",
            "Control Gap Analysis",
            "Resource Planning",
            "Timeline Definition"
          ]
        }
        ResultPath = "$.plan_output"
        Next = "Do"
        Retry = [{
          ErrorEquals     = ["Lambda.ServiceException", "Lambda.AWSLambdaException"]
          IntervalSeconds = 2
          MaxAttempts     = 3
          BackoffRate     = 2.0
        }]
        Catch = [{
          ErrorEquals = ["States.ALL"]
          Next = "HandleError"
        }]
      }
      Do = {
        Type     = "Task"
        Resource = aws_lambda_function.security_implementation.arn
        Parameters = {
          "cycle_id.$" = "$.Execution.Name"
          "phase" = "Do"
          "plan.$" = "$.plan_output"
          "implementation_tasks" = [
            "Deploy Controls",
            "Update Procedures",
            "Train Staff",
            "Configure Tools"
          ]
        }
        ResultPath = "$.do_output"
        Next = "Check"
        TimeoutSeconds = 3600
      }
      Check = {
        Type     = "Task"
        Resource = aws_lambda_function.security_assessment.arn
        Parameters = {
          "cycle_id.$" = "$.Execution.Name"
          "phase" = "Check"
          "implementation.$" = "$.do_output"
          "assessment_criteria" = [
            "Control Effectiveness",
            "Compliance Status",
            "Performance Metrics",
            "User Feedback"
          ]
        }
        ResultPath = "$.check_output"
        Next = "EvaluateResults"
      }
      EvaluateResults = {
        Type = "Choice"
        Choices = [
          {
            Variable = "$.check_output.success_rate"
            NumericGreaterThanEquals = 95
            Next = "Act"
          }
        ]
        Default = "RemediationRequired"
      }
      RemediationRequired = {
        Type = "Task"
        Resource = aws_lambda_function.security_remediation.arn
        Parameters = {
          "issues.$" = "$.check_output.issues"
          "priority" = "High"
        }
        Next = "Act"
      }
      Act = {
        Type     = "Task"
        Resource = aws_lambda_function.security_improvement.arn
        Parameters = {
          "cycle_id.$" = "$.Execution.Name"
          "phase" =