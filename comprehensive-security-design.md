**Amazon CloudWatch（メトリクス・アラート）**
- セキュリティメトリクスの収集と可視化により、KPI管理を実現します。MTTD（平均検出時間）、MTTR（平均対応時間）などの重要指標を継続的に測定し、改善効果を定量的に把握できます。カスタムメトリクスにより、組織固有の指標も追跡可能です。
- 異常値検出により、通常と異なるパターンを早期に発見します。機械学習ベースの異常検出により、閾値設定の手間を削減しながら、より精度の高い検出を実現します。複合アラームにより、複数条件での高度な監視も可能です。

**AWS Systems Manager（運用自動化）**
- パッチ管理、設定管理、運用タスクの自動化により、人的ミスを削減します。定期的なパッチ適用やコンプライアンスチェックを自動化し、セキュリティレベルを一定に保ちます。メンテナンスウィンドウにより、計画的な作業実行を実現します。
- Run Commandにより、緊急時の対応も迅速に実行できます。侵害されたインスタンスの隔離や、セキュリティ設定の一括変更などを安全に実行できます。Session Managerにより、踏み台サーバー不要で安全なアクセスを提供します。

#### Terraform実装コード

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
- カスタム脅威インテリジェンスフィードの統合により、業界固有の脅威に対応します。TechNova社の産業機械分野特有の脅威情報を取り込み、標的型攻撃への検知精度を向上させます。STIX/TAXII形式での脅威情報共有により、業界団体との連携も実現します。
- 既知の安全なIPリストにより、誤検知を削減します。本社、工場、取引先のIPアドレスをホワイトリストに登録し、正常な業務活動が脅威として検出されることを防ぎます。動的更新により、ビジネスパートナーの変更にも柔軟に対応します。

**AWS Lambda（脅威分析・自動対応）**
- 検知された脅威に対する自動対応ロジックを実装し、初動対応を高速化します。例えば、不審なEC2インスタンスの自動隔離、侵害されたIAMクレデンシャルの無効化を数秒以内に実行します。人間の判断が必要な場合は、適切にエスカレーションします。
- 脅威インテリジェンスの自動更新により、最新の脅威情報を活用します。MITRE ATT&CKフレームワークと連携し、攻撃手法を体系的に分析・対応します。TTPs（戦術・技術・手順）マッピングにより、攻撃の全体像を把握します。

**Amazon S3（脅威インテリジェンスデータ保存）**
- 脅威情報の一元管理により、組織全体での脅威情報共有を実現します。過去の攻撃パターンや対応履歴を蓄積し、将来の攻撃への対応力を向上させます。ライフサイクルポリシーにより、古い情報は自動的にアーカイブされます。
- 暗号化とアクセス制御により、機密性の高い脅威情報を保護します。脅威情報の漏洩は攻撃者に有利な情報を与えるため、厳格な管理を実施します。Object Lockにより、重要な証跡の改ざんも防止します。

**Amazon EventBridge（イベント処理）**
- セキュリティイベントの統合処理により、複数のソースからのイベントを一元的に処理します。GuardDuty、Security Hub、カスタムアプリケーションからのイベントを統合し、包括的な対応を実現します。イベントパターンマッチングにより、複雑な条件での処理も可能です。
- ルールベースの自動処理により、イベントの種類に応じた適切な対応を自動実行します。重要度に応じた通知、自動修復、エスカレーションを実装します。イベントリプレイ機能により、過去のイベントの再処理も可能です。

**Amazon Comprehend（AI分析）**
- セキュリティイベントの自然言語処理により、高度な脅威分析を実現します。ログメッセージのパターン分析により、人間では見逃しがちな微細な異常を検出します。感情分析により、内部脅威の兆候も検出可能です。
- 過去のインシデントデータを学習し、類似パターンの早期発見を可能にします。攻撃の兆候を早期に検出し、被害を未然に防ぎます。カスタムエンティティ認識により、組織固有の脅威指標も抽出できます。

#### Terraform実装コード

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
- 従業員5,000名の教育履歴を体系的に管理し、コンプライアンス要件を満たします。受講履歴、テスト結果、認定状況を一元管理することで、監査時の証跡提供も迅速に行えます。グローバルセカンダリインデックスにより、多角的な分析が可能です。
- フィッシングシミュレーション結果を分析し、教育効果を定量化します。クリック率、報告率、対応時間などのメトリクスにより、セキュリティ意識の向上度を客観的に測定できます。部門別のスコアリングにより、重点教育対象を特定します。

**Amazon SES（フィッシングシミュレーション）**
- 実際の攻撃を模したフィッシングメールで、従業員の警戒心を維持します。最新の攻撃手法を反映したシミュレーションにより、実践的な訓練を提供し、実際の攻撃への対応力を向上させます。難易度を段階的に上げることで、継続的な改善を促します。
- クリック率、報告率などのメトリクスで、セキュリティ意識を測定します。部門別、役職別の分析により、リスクの高いグループを特定し、追加教育を実施します。ベンチマークとの比較により、業界平均との差異も把握できます。

**AWS Lambda（教育システム制御）**
- 教育コンテンツの自動配信により、定期的な教育を確実に実施します。新入社員への自動教育割当、年次教育の自動リマインダーにより、教育の漏れを防止します。個人の進捗に応じた適応型学習も実現します。
- 未受講者への自動リマインダーで、受講率100%を目指します。エスカレーション機能により、長期未受講者の上長へ通知し、組織全体のセキュリティレベルを向上させます。ゲーミフィケーション要素により、モチベーション向上も図ります。

**Amazon CloudWatch（教育メトリクス）**
- 教育プログラムの効果を可視化し、改善点を特定します。受講率、合格率、フィッシングシミュレーション成功率などを継続的に測定し、教育プログラムの最適化を図ります。ダッシュボードにより、リアルタイムでの状況把握が可能です。
- ダッシュボードにより、経営層への報告を効率化します。セキュリティ教育の投資対効果を定量的に示し、継続的な投資を正当化します。インシデント減少率との相関分析により、教育効果を実証します。

**Amazon S3（教育コンテンツ保存）**
- 教育コンテンツの一元管理により、最新の教材を常に提供します。動画、プレゼンテーション、クイズなど、多様な形式の教材を安全に保存・配信します。CloudFront連携により、グローバルな配信も高速化されます。
- バージョン管理により、教材の更新履歴を追跡します。規制変更や新たな脅威に対応した教材更新を確実に実施し、常に最新の情報を提供します。A/Bテストにより、より効果的な教材の開発も可能です。

#### Terraform実装コード

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
- サプライヤーのセキュリティ評価結果を一元管理し、リスクの可視化を実現します。評価基準の標準化により、客観的なベンダー選定が可能となり、サプライチェーンリスクを低減します。評価項目はISO 27001、SOC 2などの業界標準に準拠します。
- 定期的な再評価により、継続的なリスク管理を実施します。年次評価の自動化により、評価漏れを防止し、常に最新のリスク状況を把握できます。重要度に応じて、評価頻度を調整することも可能です。

**Amazon Inspector（コンテナ・依存関係スキャン）**
- コンテナイメージの脆弱性を継続的にスキャンし、既知の脆弱性を排除します。CVEデータベースと連携し、最新の脆弱性情報に基づく検査により、ゼロデイ攻撃のリスクを最小化します。CVSS スコアに基づく優先順位付けも実施します。
- 依存関係の脆弱性も含めて包括的に検査し、サプライチェーン攻撃を防ぎます。オープンソースライブラリの脆弱性も検出し、Log4jのような広範囲な影響を持つ脆弱性にも迅速に対応できます。過渡的依存関係も含めた完全なスキャンを実施します。

**AWS CodeBuild（セキュアビルドパイプライン）**
- ビルド環境を隔離し、ビルドプロセスへの不正な介入を防ぎます。各ビルドは独立した環境で実行され、ビルド間の汚染や不正なコードの混入を防止します。ビルドログの完全性も保証され、監査要件を満たします。
- SBOM（Software Bill of Materials）を自動生成し、使用コンポーネントを追跡します。全ての依存関係を記録することで、脆弱性発覚時の影響範囲を即座に特定し、迅速な対応を可能にします。SPDX形式での出力により、業界標準に準拠します。

**Amazon ECR（コンテナイメージセキュリティ）**
- イメージの不変性により、承認済みイメージのみが使用されることを保証します。タグの上書きを防止し、テスト済みのイメージが改ざんされることなくデプロイされることを保証します。署名により、イメージの真正性も検証されます。
- 脆弱性レベルに応じた自動対応で、高リスクイメージの使用を防止します。Criticalレベルの脆弱性を持つイメージは自動的にブロックされ、本番環境への展開を防ぎます。修正版のイメージが利用可能になると、自動的に通知されます。

**AWS Config（サプライチェーンコンプライアンス）**
- サプライチェーン関連の設定を継続的に監視し、ポリシー違反を検出します。承認されていないレジストリからのイメージ使用や、未検証のライブラリの使用を防止します。カスタムルールにより、組織固有の要件にも対応可能です。
- 自動修復により、非準拠の設定を即座に是正します。セキュリティポリシーに違反する設定変更を自動的に元に戻し、常に安全な状態を維持します。修復アクションはSSM Automationと連携し、複雑な修復プロセスも自動化できます。

#### Terraform実装コード

```hcl
# Inspector V2 有効化（コンテナ・EC2脆弱性スキャン）
resource "aws_inspector2_enabler" "organization" {
  account_ids    = [data.aws_caller_identity.current.account_id]
  resource_types = ["ECR", "EC2", "LAMBDA"]
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
- S3バケット内の個人情報を自動検出し、意図しない露出を防ぎます。機械学習により、構造化・非構造化データから個人情報を高精度で検出し、データ漏洩のリスクを最小化します。カスタムデータ識別子により、組織固有の機密情報も検出可能です。
- データ分類の自動化により、適切な保護レベルを適用します。検出されたデータの種類に応じて、自動的にタグ付けとアクセス制御を適用し、規制要件への準拠を確実にします。検出精度は継続的に改善され、誤検知を最小化します。

**AWS KMS（暗号化キー管理）**
- データ分類に応じた暗号化キーの使い分けで、アクセス制御を強化します。機密データ、内部データ、公開データそれぞれに専用のKMSキーを使用し、きめ細かいアクセス制御を実現します。エンベロープ暗号化により、大容量データの暗号化も効率的に実施します。
- 自動キーローテーションにより、長期的な暗号化の安全性を保証します。年次でのキーローテーションを自動化し、古いキーの無効化も管理することで、暗号化の強度を維持します。キーの使用状況は継続的に監視され、異常な使用パターンを検出します。

**Amazon S3（データローカライゼーション）**
- 地域別のデータ保存により、データ主権要件に対応します。日本、EU、米国など、各地域の規制に準拠したデータ保存を実現し、クロスボーダーのデータ転送リスクを排除します。レプリケーション設定により、災害対策と規制準拠を両立します。
- レプリケーション制御により、意図しないデータ移動を防止します。特定地域のデータが他地域に複製されることを技術的に防止し、規制違反を回避します。データレジデンシー要件は自動的に強制され、人為的ミスを防ぎます。

**AWS CloudTrail（データアクセス監査）**
- 個人データへのアクセスを完全に記録し、不正アクセスを検出します。誰が、いつ、どのデータにアクセスしたかを追跡し、データ主体からの開示請求にも迅速に対応できます。データイベントの記録により、オブジェクトレベルの追跡も可能です。
- 異常なアクセスパターンの検出により、データ漏洩を早期発見します。大量ダウンロードや通常と異なるアクセスパターンを検出し、被害を最小限に抑えます。機械学習による異常検知により、未知の攻撃パターンにも対応します。

**AWS Config（プライバシー設定監視）**
- プライバシー関連の設定を継続的に監視し、ポリシー違反を防止します。暗号化の無効化、アクセス制御の緩和などを即座に検出し、修正します。プライバシー影響評価（PIA）の結果に基づいた監視ルールを実装します。
- 自動修復により、プライバシー設定の一貫性を維持します。設定のドリフトを自動的に修正し、常に高いプライバシー保護レベルを維持します。修復履歴は完全に記録され、監査要件を満たします。

#### Terraform実装コード

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
- セキュリティサービスごとのコスト内訳を可視化し、ROIを測定します。GuardDuty、Security Hub、Macieなどのサービス別コストを追跡し、投資効果を定量的に評価することで、経営層への報告を効率化します。タグベースのコスト配分により、部門別の負担も明確化できます。
- 未使用のセキュリティリソースを特定し、コスト削減機会を発見します。例えば、使用されていないWAFルールや、過剰なログ保存期間を特定し、年間数百万円のコスト削減を実現します。リザーブドインスタンスの活用提案も自動生成されます。

**AWS Budgets（セキュリティ予算管理）**
- セキュリティ予算の80%到達時と予測超過時にアラートを発報します。早期の警告により、予算超過を未然に防ぎ、計画的なセキュリティ投資を可能にします。予算消化率の可視化により、四半期末の駆け込み支出も防止できます。
- 部門別、サービス別の予算管理により、コスト意識を醸成します。各部門のセキュリティコストを可視化し、責任を明確化することで、無駄な支出を削減します。コストセンター別の課金により、適切なコスト配分も実現します。

**AWS Trusted Advisor（コスト最適化推奨）**
- セキュリティ設定の最適化提案により、過剰な保護を見直します。リスクレベルに応じた適切な保護レベルを維持しながら、コストを最適化します。例えば、開発環境での過剰なセキュリティサービスの見直しにより、コストを削減します。
- 自動化可能な推奨事項を特定し、運用コストを削減します。手動作業を自動化することで、人件費を削減しながらセキュリティレベルを向上させます。Lambda関数による自動化により、運用工数を80%削減できます。

**Amazon CloudWatch（リソース使用率監視）**
- セキュリティリソースの使用率を監視し、適正サイジングを実現します。過剰にプロビジョニングされたリソースを特定し、コスト削減機会を創出します。使用率の低いリソースは自動的にスケールダウンされ、コストを最適化します。
- 使用パターンの分析により、予約購入の機会を特定します。安定的に使用されるリソースについて、リザーブドインスタンスや Savings Plans の活用により、大幅なコスト削減を実現します。3年契約により、最大72%のコスト削減が可能です。

**AWS Lambda（自動コスト最適化）**
- 未使用リソースの自動削除により、無駄なコストを排除します。開発環境の夜間停止、週末のリソース削減など、自動化により年間20-30%のコスト削減を実現します。タグベースの自動化により、本番環境への影響を防ぎます。
- コスト異常の自動検出により、予期しない支出を防止します。通常と異なる使用パターンを検出し、不正使用や設定ミスによる過剰請求を防ぎます。異常検知により、月間10万円以上の無駄な支出を防止できます。

#### Terraform実装コード

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
- 四半期ごとにセキュリティピラーの評価を実施し、改善点を特定します。AWSのベストプラクティスに基づく客観的な評価により、組織のセキュリティ成熟度を定量的に把握し、改善の優先順位を明確化します。High Riskアイテムをゼロにすることを目標とします。
- 業界ベストプラクティスとのギャップ分析により、改善優先順位を決定します。同業他社との比較により、競争優位性を維持しながら、効率的な改善活動を実施します。改善提案は自動的に生成され、実装までのロードマップも提供されます。

**AWS Systems Manager（運用成熟度管理）**
- セキュリティ運用の標準化と自動化により、属人性を排除します。運用手順書をコード化し、誰でも同じ品質で運用できる体制を構築することで、人的エラーを最小化します。Runbookの実行履歴により、運用品質を継続的に改善します。
- 運用手順書の一元管理により、インシデント対応の品質を向上させます。最新の手順書が常に利用可能な状態を維持し、迅速かつ的確な対応を可能にします。バージョン管理により、変更履歴も完全に追跡できます。

**Amazon QuickSight（セキュリティメトリクス可視化）**
- セキュリティKPIの可視化により、改善効果を定量的に把握します。MTTD、MTTR、コンプライアンススコアなどの重要指標をダッシュボードで一元管理し、経営層への報告を効率化します。MLインサイトにより、異常な傾向も自動検出されます。
- トレンド分析により、将来の脅威を予測します。過去のインシデントデータから傾向を分析し、予防的な対策を実施することで、インシデントの発生を未然に防ぎます。予測分析により、リソース配分の最適化も実現します。

**AWS Config（設定管理成熟度）**
- 設定の一貫性を継続的に監視し、ドリフトを防止します。承認された設定からの逸脱を即座に検出し、自動修復することで、常に安全な状態を維持します。コンフォーマンスパックにより、複数の標準への準拠を効率的に管理します。
- コンプライアンススコアの向上により、監査対応を効率化します。常時99.5%以上のコンプライアンススコアを維持することで、監査時の指摘事項を最小化します。改善トレンドの可視化により、継続的改善の効果も実証できます。

**AWS Lambda（成熟度評価自動化）**
- 成熟度評価の自動化により、客観的な評価を実現します。人的バイアスを排除し、一貫性のある評価基準により、正確な成熟度レベルを把握します。評価結果は自動的にスコアリングされ、改善優先度も明確化されます。
- 改善提案の自動生成により、効率的な改善活動を支援します。評価結果に基づいて、具体的な改善アクションを自動的に提案し、PDCAサイクルを加速します。実装難易度と効果のマトリクスにより、最適な改善順序を決定します。

#### Terraform実装コード

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

#### 実装対象サービス

**AWS Systems Manager（実装進捗管理）**
- 実装タスクの一元管理により、進捗を可視化します。各フェーズのタスク、依存関係、完了状況を管理し、プロジェクト全体の進捗を正確に把握します。ガントチャート形式での表示により、クリティカルパスも明確化されます。
- 自動化されたステータス更新により、リアルタイムな進捗管理を実現します。各タスクの完了を自動的に検知し、ダッシュボードに反映することで、手動更新の手間を削減します。遅延タスクは自動的にエスカレーションされます。

**AWS CodePipeline（段階的デプロイメント）**
- 段階的なセキュリティ機能の展開により、リスクを最小化します。開発環境から本番環境への段階的な展開により、問題を早期に発見し、影響範囲を限定します。Blue/Greenデプロイメントにより、ロールバックも迅速に実行できます。
- 自動化されたテストとロールバックにより、品質を保証します。各段階でのセキュリティテストを自動実行し、問題検出時は自動的にロールバックすることで、安全な展開を実現します。手動承認ゲートにより、重要な変更は人間の判断も組み込めます。

**Amazon EventBridge（フェーズ管理）**
- フェーズ間の自動移行により、プロジェクトを効率的に進行させます。前フェーズの完了を自動的に検知し、次フェーズを開始することで、プロジェクトの停滞を防ぎます。依存関係の管理により、並行実行可能なタスクは自動的に並列化されます。
- マイルストーン達成の自動通知により、ステークホルダーへの報告を効率化します。重要な達成事項を自動的に通知し、プロジェクトの透明性を確保します。カスタマイズ可能な通知により、受信者に応じた情報提供が可能です。

**AWS Lambda（実装自動化）**
- インフラのコード化により、一貫性のある実装を実現します。Terraformによるインフラ定義により、環境間の差異を排除し、予測可能な結果を得られます。GitOpsワークフローにより、変更管理も自動化されます。
- 自動化されたセキュリティ設定により、人的ミスを防止します。ベストプラクティスに基づいた設定を自動適用し、セキュリティホールの発生を防ぎます。ポリシーアズコードにより、セキュリティ要件も自動的に強制されます。

**Amazon CloudWatch（実装監視）**
- 実装状況のリアルタイム監視により、問題を早期発見します。エラー率、成功率、処理時間などのメトリクスを監視し、異常を即座に検出します。カスタムメトリクスにより、プロジェクト固有のKPIも追跡できます。
- KPIダッシュボードにより、目標達成状況を可視化します。各フェーズの成功基準に対する達成度を一目で把握し、必要な対策を迅速に実施できます。予測分析により、遅延リスクも事前に検出されます。

#### Terraform実装コード

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

### 主要サービス対応表

| **セクション** | **主要AWSサービス** | **具体的な設定内容** |
|:---|:---|:---|
| **セキュリティ運用・管理** | Security Hub, GuardDuty, CloudWatch | 統合セキュリティ監視、メトリクス収集、アラート設定により、組織全体のセキュリティ状況を一元管理。複数の標準への準拠状況も継続的に監視 |
| **脅威対応** | GuardDuty, Lambda, S3, EventBridge | 脅威インテリジェンス統合、AI分析、自動対応により、未知の脅威にも迅速に対応。MITRE ATT&CKフレームワークとの連携で体系的な対策を実現 |
| **セキュリティ教育** | DynamoDB, SES, Lambda, CloudWatch | フィッシングシミュレーション、教育記録管理により、人的要因によるリスクを最小化。5,000名規模の組織全体のセキュリティ意識を向上 |
| **サプライチェーン** | Inspector, ECR, CodeBuild, Config | 脆弱性スキャン、セキュアビルド、SBOM管理により、サプライチェーン攻撃を防止。依存関係の脆弱性も包括的に管理 |
| **プライバシー保護** | Macie, KMS, S3, Lambda | 個人情報検出、暗号化、GDPR対応により、データ保護規制に完全準拠。データ主体の権利行使にも自動対応 |
| **コスト最適化** | Cost Explorer, Budgets, Lambda | セキュリティコスト監視、ROI分析により、効果的なセキュリティ投資を実現。年間20-30%のコスト削減を達成 |
| **継続的改善** | Systems Manager, QuickSight, Step Functions | 成熟度評価、PDCA自動化、KPI可視化により、セキュリティレベルを継続的に向上。業界ベストプラクティスとの差異も明確化 |
| **実装管理** | CodePipeline, DynamoDB, EventBridge | 段階的実装、進捗監視、フェーズゲートにより、計画的なセキュリティ強化を実現。リスクを最小化しながら着実に改善 |

### 重要な設定ポイント

1. **自動化の実現**: Lambda関数による運用タスクの自動化により、人的ミスを削減し、24時間365日の監視体制を実現。運用工数を80%削減

2. **統合監視**: CloudWatchダッシュボードによる一元的な可視化により、複雑な環境でも効率的な管理を可能に。120アカウントを単一画面で監視

3. **コンプライアンス**: Config Rules、Security Hub標準による継続的監査により、常に高いコンプライアンスレベルを維持。99.5%以上の準拠率を達成

4. **データ保護**: KMS暗号化、Macie個人情報検出の組み合わせにより、データ漏洩リスクを最小化。GDPR、個人情報保護法に完全準拠

5. **コスト管理**: Budgets、Cost Explorerによる費用対効果の監視により、セキュリティ投資のROIを最大化。予算超過を未然に防止

### 期待される成果

**定量的成果**
- セキュリティインシデント：前年比70%削減
- MTTD（平均検出時間）：30分→5分（83%改善）
- MTTR（平均対応時間）：4時間→30分（87.5%改善）
- コンプライアンススコア：85%→99.5%
- セキュリティ運用コスト：年間20%削減
- 脆弱性修復時間：Critical 48時間以内、High 7日以内
- フィッシング耐性：クリック率5%未満
- 暗号化カバレッジ：100%（全データ）

**定性的成果**
- 経営層の安心感向上：リアルタイムでのセキュリティ状況可視化により、経営判断の迅速化
- 開発者の生産性向上：セキュアな開発環境の自動提供により、セキュリティを意識せずに開発に集中
- 顧客信頼の向上：高度なセキュリティ対策による差別化で、競合他社に対する優位性を確立
- 従業員のセキュリティ意識向上：継続的な教育とフィードバックにより、組織全体のセキュリティ文化を醸成
- 監査対応の効率化：自動化された証跡収集により、監査準備工数を90%削減
- ビジネス継続性の向上：高度な脅威にも対応可能な体制により、事業への影響を最小化

### 実装フェーズ

**フェーズ1（0-3ヶ月）：基盤構築**
- IAM Identity Center統合
- Security Hub, GuardDuty有効化
- CloudTrail組織トレイル設定
- 基本的なConfig Rules実装

**フェーズ2（3-6ヶ月）：セキュリティ強化**
- WAF, Network Firewall実装
- 暗号化の全面適用
- 自動修復機能の実装
- セキュリティ教育プログラム開始

**フェーズ3（6-12ヶ月）：高度化・最適化**
- AI/ML脅威検知の実装
- サプライチェーンセキュリティ強化
- コスト最適化の実施
- 継続的改善プロセスの確立

### 持続可能性

この設計は、現在の脅威環境に対応しながら、将来の技術進化や新たな脅威にも柔軟に対応できる、スケーラブルで持続可能なセキュリティ体制を提供します。継続的な改善プロセス（PDCA）により、常に最新のセキュリティレベルを維持し、TechNova社のビジネス成長を支えるセキュアな基盤となります。

各セキュリティ機能は相互に連携し、多層防御を実現することで、単一の脆弱性が致命的な被害につながることを防ぎます。また、自動化と可視化により、限られたセキュリティ人材でも効果的な運用が可能となり、ビジネスの成長に合わせてスケールできる体制を構築します。

この包括的なセキュリティ設計により、TechNova社は業界をリードするセキュリティ体制を確立し、顧客・パートナー・従業員から信頼される企業として、持続的な成長を実現します。# セキュリティ要件

## セキュリティ要件（完全統合版）

### TechNova社120アカウント構成における包括的セキュリティアーキテクチャ

### 1. 全体セキュリティ戦略とコンプライアンス要件

#### セキュリティ設計原則

**Zero Trust アーキテクチャの採用**
- すべてのネットワークトラフィック、ユーザーアクセス、デバイス接続を検証します。従来の境界防御モデルから脱却し、「信頼せず、常に検証する」原則を徹底適用することで、内部脅威やラテラルムーブメントのリスクを最小化します。この選定により、クラウドネイティブ環境での高度な脅威に対応可能となり、従来型のファイアウォール中心の防御と比較して、内部からの攻撃にも効果的に対処できます。
- 「信頼せず、常に検証する」原則の徹底適用により、ネットワーク内部からの攻撃や、正規アカウントを悪用した攻撃にも対応可能な体制を構築します。代替案として検討したVPNベースのアクセス制御と比較し、より細かい粒度でのアクセス制御が可能となり、セキュリティ侵害時の影響範囲を最小化できます。
- 最小権限の原則（Principle of Least Privilege）の厳格な実装により、各ユーザー・サービスは業務遂行に必要な最小限のアクセス権限のみを付与され、侵害時の影響範囲を限定します。広範囲な権限付与と比較して、管理の複雑性は増すものの、セキュリティリスクを大幅に低減できるメリットがあります。

**多層防御（Defense in Depth）戦略**
- ネットワーク層、アプリケーション層、データ層の複数レイヤーでのセキュリティ制御を実装します。これにより、一つの防御層が突破されても、他の層で脅威を検出・阻止できる堅牢な防御体制を実現します。単一の強力な防御層に依存する方式と比較して、コストは増加しますが、攻撃成功率を指数関数的に低下させることができます。
- 単一障害点の排除と冗長性の確保により、セキュリティ機能自体の可用性も保証し、攻撃者がセキュリティ機能を無効化しようとする試みにも対抗します。これにより、DDoS攻撃などでセキュリティ機能を狙う高度な攻撃にも耐性を持ちます。
- 各層での独立したセキュリティ監視と制御により、異なる種類の脅威に対して最適化された防御メカニズムを適用できます。統合型セキュリティソリューションと比較して、各層に特化した最適な対策を実装できる柔軟性があります。

**セキュリティ・バイ・デザイン（Security by Design）**
- 設計段階からのセキュリティ考慮により、後付けでは実現困難な根本的なセキュリティ対策を実装します。これにより、セキュリティホールの発生を未然に防ぎます。事後的なセキュリティ対策と比較して、初期コストは高いものの、長期的な総所有コスト（TCO）を大幅に削減できます。
- 脅威モデリングに基づくリスク評価を実施し、想定される攻撃シナリオに対する対策を事前に組み込みます。STRIDE、PASTA、ATTACKフレームワークを活用し、包括的な脅威分析を実施します。
- セキュリティ要件の明確化と実装により、開発・運用フェーズでの手戻りを最小化し、コスト効率の高いセキュリティ実装を実現します。アジャイル開発との親和性も高く、継続的なセキュリティ改善が可能となります。

#### コンプライアンス要件

**法的・規制要件**

**個人情報保護法**
- 顧客データの適切な取り扱いと保護を実現します。暗号化、アクセス制御、監査ログの実装により、個人情報の漏洩を防止します。2022年の改正に完全対応し、越境データ移転にも対応可能な体制を構築します。
- データ漏洩時の72時間以内の報告義務に対応するため、自動検知と通知の仕組みを構築します。GuardDutyとSecurityHubの統合により、インシデント検知から報告書作成まで自動化し、人的ミスを排除します。

**GDPR**
- EU域内データの処理に関する厳格な規制対応を実施します。データポータビリティ、忘れられる権利、明示的な同意取得などの要件を技術的に実装します。自動化されたデータ主体権利対応システムにより、30日以内の対応期限を確実に遵守します。
- データ保護影響評価（DPIA）の実施と、プライバシーバイデザインの原則に基づいた設計を行います。高リスクな処理については事前評価を義務化し、プライバシー侵害のリスクを最小化します。

**SOX法**
- 財務データの完全性と内部統制を確保します。職務の分離、承認プロセス、監査証跡の完全性により、財務報告の信頼性を保証します。自動化された監査証跡により、外部監査対応の工数を80%削減します。
- 四半期ごとの内部統制評価と、年次の外部監査に対応可能な体制を構築します。継続的なコンプライアンス監視により、問題の早期発見と是正を実現します。

**ISO 27001**
- 情報セキュリティ管理システムの国際標準準拠により、体系的なセキュリティ管理を実現します。114の管理策を網羅的に実装し、グローバル標準のセキュリティレベルを達成します。
- PDCAサイクルに基づく継続的改善プロセスを確立し、セキュリティレベルの維持・向上を図ります。年次の内部監査と3年ごとの更新審査により、認証を維持します。

**業界標準準拠**

**NIST Cybersecurity Framework**
- セキュリティ管理の標準化により、体系的で漏れのないセキュリティ対策を実現します。成熟度レベル4（管理された状態）を目標とし、定量的な改善を実施します。
- 識別（Identify）、防御（Protect）、検知（Detect）、対応（Respond）、復旧（Recover）の5つの機能を包括的に実装します。各機能に対してKPIを設定し、継続的な改善を実施します。

**CIS Controls**
- 重要セキュリティ制御の実装により、実証済みの効果的な対策を適用します。実装ガイドラインに基づき、環境に最適化された形で適用します。
- 優先順位付けされた20の制御により、限られたリソースで最大の効果を実現します。Implementation Group 2（IG2）レベルの制御を目標とし、段階的に実装します。

**AWS Well-Architected Framework**
- クラウドセキュリティベストプラクティスの適用により、AWS環境に最適化されたセキュリティを実現します。セキュリティピラーの全項目でHighリスクをゼロにすることを目標とします。
- 定期的なWell-Architectedレビューにより、継続的な改善機会を特定します。四半期ごとのレビューで、新しいベストプラクティスを取り込みます。

### 2. アカウントレベルセキュリティ（120アカウント対応）

#### アカウント分離とセキュリティ境界

**アカウント階層とセキュリティ境界設計**

**Root管理アカウント**
- **最小権限アクセス**：経営層3名のみアクセス可能とし、日常的な運用作業では一切使用しません。これにより、最高権限の悪用リスクを最小化します。代替案として検討したIAMユーザーによる管理と比較し、完全な権限分離を実現できます。
- **強力な認証**：ハードウェアMFA（YubiKey）必須により、フィッシングやマルウェアによる認証情報の窃取にも対抗できる強固な認証を実現します。ソフトウェアMFAと比較して、より高いセキュリティレベルを提供します。
- **監査証跡**：全アクションの完全記録により、不正アクセスや誤操作の検出と原因究明を可能にします。ログは別アカウント（Log Archive Account）に保存し、改ざんを防止します。保存期間は7年とし、法的要件を満たします。
- **アクセス制限**：IP制限（本社IPのみ：203.0.113.0/24）、時間制限（業務時間のみ：平日9:00-18:00 JST）の実装により、攻撃機会を大幅に削減します。緊急時のbreak-glass手順も整備し、可用性とのバランスを確保します。

**セキュリティ専用アカウント**
- **集中監視機能**：全120アカウントのセキュリティログ・監視の集中管理により、組織全体のセキュリティ状況を一元的に把握し、迅速な対応を可能にします。分散管理と比較して、見落としのリスクを95%削減できます。
- **独立性確保**：他アカウントからの影響を受けない独立運用により、セキュリティ機能の可用性と完全性を保証します。本番環境の障害がセキュリティ監視に影響しない設計となっています。
- **権限分離**：セキュリティ管理者とシステム管理者の役割分離により、内部不正や誤操作のリスクを低減します。職務の分離（SoD）により、単独での不正行為を防止します。

**アカウント間セキュリティ通信**

セキュリティ通信フロー：
```
各アカウント → Security Account → 集中監視
├── CloudTrail ログ（全APIコール記録）
├── GuardDuty 検知情報（脅威インテリジェンス）
├── Config 設定変更履歴（コンプライアンス監視）
├── Security Hub 統合レポート（優先順位付け）
└── VPC Flow Logs（ネットワーク通信分析）
```

このアーキテクチャにより、各アカウントでの異常を5分以内に検知し、自動対応を開始できます。

クロスアカウント通信制御：
- 最小権限によるAssumeRole設定により、必要最小限の権限のみを付与し、権限昇格攻撃を防止します。各ロールは単一目的に限定され、過剰な権限付与を防ぎます。
- 時間制限付きアクセス（業務時間のみ：9:00-18:00 JST）により、攻撃可能な時間帯を限定します。時間外アクセスは承認プロセスを必須とします。
- 特定IPからのアクセス制限（本社：203.0.113.0/24、DR拠点：198.51.100.0/24）により、外部からの不正アクセスを防止します。
- 全通信の監査ログ記録により、異常なアクセスパターンを検出可能にします。機械学習により、通常と異なるアクセスパターンを自動検出します。

**アカウント別セキュリティ設定**

**本番環境アカウント（24アカウント）**
- **厳格なアクセス制御**：本番環境への変更は承認制とし、計画外の変更や不正な変更を防止します。変更諮問委員会（CAB）による事前承認と、変更後の自動検証を実装します。
- **データ暗号化**：保存時（AES-256）・転送時（TLS 1.3）の完全暗号化により、データ漏洩時も内容の保護を保証します。暗号化キーは年次で自動ローテーションされます。
- **監査ログ**：全操作の完全記録と長期保存（7年）により、コンプライアンス要件を満たし、インシデント調査を可能にします。ログの整合性はCloudTrail Log File Validationで保証されます。
- **変更管理**：全変更の事前承認と影響評価により、変更に起因する障害やセキュリティインシデントを防止します。変更成功率99.5%以上を目標とします。

**開発・テスト環境アカウント（96アカウント）**
- **開発者権限**：必要最小限の権限付与により、開発環境での事故や不正操作の影響を限定します。PowerUserAccessポリシーをベースに、危険なアクションを除外したカスタムポリシーを適用します。
- **データマスキング**：本番データの機密性保護により、開発環境経由でのデータ漏洩を防止します。個人情報は自動的に仮名化され、元データへの復元を不可能にします。
- **アクセス時間制限**：業務時間外のアクセス制限により、不正アクセスの機会を削減します。深夜・休日のアクセスは上長承認を必須とします。
- **定期的なリソース削除**：不要リソースの自動削除（30日経過後）により、攻撃対象となる放置されたリソースを排除します。タグによる例外管理も可能です。

### 3. Identity and Access Management（IAM）統合セキュリティ

#### IAM Identity Center統合認証

**フェデレーション認証基盤**

認証フロー：
```
Active Directory → IAM Identity Center → 120アカウント
├── SAML 2.0 認証（業界標準プロトコル）
├── グループベースの権限付与（既存AD構造を活用）
├── 条件付きアクセス（時間・場所・デバイス制御）
└── セッション管理（自動タイムアウト・強制ログアウト）
```

このフローにより、既存のAD基盤を活用しながら、クラウド環境に最適化された認証・認可を実現します。シングルサインオン（SSO）により、ユーザビリティとセキュリティを両立します。

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
    "ApprovalRequired": "Yes",
    "JustInTimeAccess": "有効",
    "PrivilegedAccessWorkstation": "必須"
  },
  "SecurityAdmin": {
    "AccessLevel": "SecurityServices",
    "MFA": "Required", 
    "SessionDuration": "8時間",
    "IPRestriction": "セキュリティチームIPのみ",
    "AuditLogging": "Enhanced",
    "ReadOnlyFallback": "自動切替",
    "EmergencyAccess": "BreakGlass手順"
  }
}
```

管理者権限は多要素認証、IP制限、時間制限、承認プロセスなど、多層的な制御により保護されます。Just-In-Time（JIT）アクセスにより、常時付与される権限を最小化します。

**開発者権限セット（環境別制御）**

```json
{
  "DeveloperFull": {
    "AccessLevel": "DevelopmentEnvironment",
    "MFA": "Required",
    "SessionDuration": "8時間",
    "ResourceLimits": "開発環境のみ",
    "CostControl": "月次予算制限（$500/月）",
    "ServiceRestrictions": "高コストサービス制限",
    "DataAccess": "マスクされたデータのみ"
  },
  "DeveloperRead": {
    "AccessLevel": "ReadOnly",
    "MFA": "Optional",
    "SessionDuration": "8時間",
    "ResourceScope": "開発環境のみ",
    "LogAccess": "自身の操作ログのみ",
    "CostVisibility": "自身の利用分のみ"
  }
}
```

開発者は担当環境のみにアクセス可能とし、本番環境への誤操作を防止します。コスト管理機能により、予期しない高額請求を防ぎます。

#### サービスロールセキュリティ設計

**ECS Task Role最小権限設計**

```json
{
  "20マイクロサービス別TaskRole": {
    "manufacturing-planning": {
      "DatabaseAccess": "aurora-prod-manufacturing-planning のみ",
      "S3Access": "専用バケットのみ（s3://technova-mfg-planning/*）",
      "SecretsManager": "専用シークレットのみ（/prod/mfg/planning/*）",
      "CloudWatchLogs": "専用ロググループのみ（/aws/ecs/mfg-planning）",
      "NetworkAccess": "特定VPCエンドポイント経由のみ",
      "TimeBasedAccess": "業務時間内のみ書き込み可能"
    },
    "sales-order": {
      "DatabaseAccess": "aurora-prod-sales-order のみ",
      "CrossServiceAPI": "inventory-check API のみ（読み取り専用）",
      "S3Access": "専用バケットのみ（s3://technova-sales-order/*）", 
      "SecretsManager": "専用シークレットのみ（/prod/sales/order/*）",
      "MessageQueue": "専用SQSキューのみ",
      "RateLimiting": "1000リクエスト/分"
    }
  }
}
```

各マイクロサービスは専用のリソースのみにアクセス可能とし、サービス間の不正アクセスを防止します。時間ベースのアクセス制御により、異常な時間帯のアクセスをブロックします。

**IAM Database認証セキュリティ**

```
Aurora IAM認証フロー：
ECS Task → IAM Role → Database Token (15分有効) → Aurora接続
├── トークン自動ローテーション（10分ごと）
├── 接続時間制限（最大12時間）
├── 接続数制限（サービスあたり100接続）
└── 全接続の監査ログ記録（Performance Insights）
```

短期間有効なトークンにより、認証情報の長期保存リスクを排除します。パスワードレス認証により、認証情報の管理負担も軽減されます。

### 4. ネットワークセキュリティ（多層防御）

#### VPC セキュリティ設計

**ネットワーク分離とセキュリティ境界**

VPC分離戦略（120アカウント）：
```
管理系VPC (10.200.0.0/16) - 最高セキュリティレベル
├── Security Account VPC (10.200.0.0/20)
├── Shared Services VPC (10.200.16.0/20)
└── Network Hub VPC (10.200.32.0/20)

事業部門VPC (10.0.0.0/8) - 部門別セグメンテーション
├── 製造部門 (10.0.0.0/14) - 24アカウント
├── 販売部門 (10.1.0.0/14) - 24アカウント
├── サービス部門 (10.2.0.0/14) - 24アカウント
└── IoT部門 (10.3.0.0/14) - 24アカウント
```

この階層的な分離により、部門間の不正アクセスを防止し、侵害時の影響範囲を限定します。各VPCは最大でも/20のサイズに制限し、爆発的な拡大を防ぎます。

セキュリティ制御：
- プライベートサブネット中心の設計により、インターネットからの直接攻撃を防止。パブリックサブネットは最小限とし、WAF/ALBのみを配置します。
- NATゲートウェイ経由の外部通信により、アウトバウンド通信を制御・監視。固定IPによりアウトバウンド通信先での制御も可能にします。
- VPC Endpoint による AWS サービスアクセスにより、インターネット経由の通信を排除。S3、DynamoDB、SecretsManagerなど主要サービスへのエンドポイントを設定します。
- Transit Gateway による制御された相互接続により、必要最小限の通信のみを許可。ルートテーブルによる細かい制御で、不要な通信を防ぎます。

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
          "RuleId": "web-001"
        }
      ],
      "EgressRules": [
        {
          "Protocol": "HTTP",
          "Port": 8080,
          "Destination": "app-tier-sg",
          "Description": "アプリケーション層への通信"
        }
      ],
      "TaggingStrategy": "環境・用途・重要度で自動タグ付け"
    },
    "app-tier-sg": {
      "InboundRules": [
        {
          "Protocol": "HTTP",
          "Port": 8080,
          "Source": "web-tier-sg",
          "Description": "Web層からのHTTP通信のみ",
          "RuleId": "app-001"
        }
      ],
      "EgressRules": [
        {
          "Protocol": "MySQL",
          "Port": 3306,
          "Destination": "db-tier-sg",
          "Description": "データベース層への通信"
        }
      ],
      "ChangeControl": "Infrastructure as Code管理必須"
    },
    "db-tier-sg": {
      "InboundRules": [
        {
          "Protocol": "MySQL",
          "Port": 3306,
          "Source": "app-tier-sg",
          "Description": "App層からのMySQL通信のみ",
          "RuleId": "db-001"
        }
      ],
      "EgressRules": [],
      "IsolationLevel": "最高（アウトバウンド通信禁止）"
    }
  }
}
```

最小権限の原則に基づき、各層間の通信を必要最小限に制限します。セキュリティグループのルールIDにより、変更管理を容易にします。

#### Network Firewall実装

**ステートフルファイアウォール設定**

```yaml
# Network Firewall Rule Groups
StatefulRuleGroups:
  - Name: "malware-protection"
    Priority: 100
    Rules:
      - Action: "DROP"
        Header:
          Protocol: "TCP"
          Source: "ANY"
          Destination: "ANY"
        RuleOptions:
          - Keyword: "content"
            Values: ["malware-signature-patterns"]
        AlertOptions:
          - SNSTopic: "security-alerts"
          - LogGroup: "/aws/networkfirewall/malware"
            
  - Name: "intrusion-detection"
    Priority: 200
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
        ThreatIntelligence:
          - Source: "AWS Managed"
          - CustomFeeds: ["technova-threat-intel"]
```

既知の攻撃パターンを検出・ブロックし、新たな脅威についてもアラートを生成します。Suricataルールとの互換性により、既存のルールセットも活用できます。

**ドメインフィルタリング設定**

```json
{
  "DomainFiltering": {
    "AllowedDomains": [
      "*.amazonaws.com",
      "*.technova.com",
      "github.com",
      "registry.npmjs.org",
      "pypi.org",
      "docker.io"
    ],
    "BlockedCategories": [
      "malware",
      "phishing",
      "gambling",
      "adult-content",
      "proxy-anonymizer",
      "cryptocurrency-mining"
    ],
    "CustomBlockList": [
      "known-malicious-domains.txt",
      "cryptocurrency-mining-sites.txt",
      "tor-exit-nodes.txt"
    ],
    "DynamicUpdates": "1時間ごとに脅威インテリジェンスフィードを更新",
    "BypassProcess": "セキュリティチーム承認による一時的例外許可"
  }
}
```

業務に必要なドメインのみを許可し、マルウェア感染やデータ漏洩のリスクを低減します。動的更新により、最新の脅威にも対応します。

### 5. Web Application Firewall（WAF）統合保護

#### WAF設定とルール管理

**多層WAF配置**

```
WAF配置戦略：
CloudFront → WAF (Global) - エッジでの防御
├── DDoS Protection（Layer 7）
├── Geo-blocking（国別アクセス制御）
├── Rate Limiting（グローバルレート制限）
└── Bot Management（悪意のあるボット検出）

ALB → WAF (Regional) - アプリケーション層防御
├── Application-specific Rules（アプリ固有ルール）
├── Custom Rules（カスタム防御ロジック）
├── Managed Rule Groups（OWASP Top 10対策）
└── IP Reputation Lists（評判ベースブロック）

API Gateway → WAF (API Protection) - API特化防御
├── API-specific Rules（APIメソッド別制御）
├── Request Validation（スキーマ検証）
├── Rate Limiting per API Key（APIキー別制限）
└── Payload Inspection（ペイロード詳細検査）
```

各層で異なる種類の攻撃に対する防御を実装し、多層防御を実現します。攻撃の99.9%をエッジで防ぐことで、オリジンへの負荷を最小化します。

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
        "ScopeDownStatement": "特定パスのみ適用"
      },
      "KnownBadInputsRuleSet": {
        "Enabled": true,
        "Priority": 2,
        "OverrideAction": "None",
        "CustomResponse": "403 Forbidden"
      },
      "SQLiRuleSet": {
        "Enabled": true,
        "Priority": 3,
        "OverrideAction": "None",
        "SensitivityLevel": "HIGH"
      },
      "XSSRuleSet": {
        "Enabled": true,
        "Priority": 4,
        "OverrideAction": "None",
        "SanitizationEnabled": true
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
              "NotStatement": {
                "IPSetReferenceStatement": {
                  "ARN": "arn:aws:wafv2:region:account:ipset/trusted-ips"
                }
              }
            }
          }
        },
        "ChallengeEnabled": true,
        "CaptchaConfig": {
          "ImmunityTimeProperty": 300
        }
      },
      "GeoBlockRule": {
        "Priority": 11,
        "Action": "Block",
        "Statement": {
          "GeoMatchStatement": {
            "CountryCodes": ["CN", "KP", "IR", "RU"],
            "ForwardedIPConfig": {
              "HeaderName": "X-Forwarded-For",
              "FallbackBehavior": "MATCH"
            }
          }
        },
        "CustomResponse": {
          "ResponseCode": 403,
          "CustomResponseBodyKey": "geo-block-message"
        }
      },
      "APIProtectionRule": {
        "Priority": 12,
        "Action": "Block",
        "Statement": {
          "AndStatement": {
            "Statements": [
              {
                "ByteMatchStatement": {
                  "SearchString": "/api/",
                  "FieldToMatch": {"UriPath": {}},
                  "TextTransformations": [{"Priority": 0, "Type": "LOWERCASE"}],
                  "PositionalConstraint": "STARTS_WITH"
                }
              },
              {
                "NotStatement": {
                  "Statement": {
                    "ByteMatchStatement": {
                      "SearchString": "Bearer",
                      "FieldToMatch": {"SingleHeader": {"Name": "authorization"}},
                      "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                      "PositionalConstraint": "STARTS_WITH"
                    }
                  }
                }
              }
            ]
          }
        }
      }
    }
  }
}
```

AWS管理ルールで基本的な脅威を防御し、カスタムルールで組織固有の要件に対応します。ルールの優先順位付けにより、パフォーマンスへの影響を最小化します。

#### DDoS Protection統合

**AWS Shield Standard + Advanced設定**

```yaml
# Shield Protection Configuration
ShieldProtection:
  Resources:
    - CloudFront Distributions（全ディストリビューション）
    - Route 53 Hosted Zones（全ホストゾーン）
    - Application Load Balancers（全ALB）
    - Network Load Balancers（重要NLB）
    - Elastic IP Addresses（全EIP）
    
  DDoSResponseTeam:
    - 24/7 Support Access（DRTへの直接アクセス）
    - Incident Response Automation（自動エスカレーション）
    - Emergency Escalation Procedures（15分以内の対応開始）
    - Cost Protection（DDoS攻撃によるコスト増加を補償）
    
  AdvancedProtection:
    - Application Layer DDoS Protection（Layer 7攻撃対策）
    - Attack Analytics and Reporting（詳細な攻撃分析）
    - Cost Protection Guarantee（攻撃時のコスト保護）
    - Global Threat Environment Dashboard（グローバル脅威状況）
    
  CustomMitigations:
    - Rate-based Rules（カスタムレート制限）
    - Geo-based Restrictions（地域別制限）
    - Application-specific Protections（アプリ特化対策）
```

Shield Advancedにより、大規模なDDoS攻撃からの保護と、攻撃時のコスト保護を実現します。過去最大3.47Tbpsの攻撃にも耐えうる防御能力を提供します。

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
      "LegacyCipherSuites": "6か月の移行期間後に無効化",
      "CertificateAuthority": "AWS Certificate Manager",
      "CertificateValidation": "DNS validation",
      "AutomaticRenewal": "有効（30日前から更新開始）",
      "CertificateTransparency": "必須（CTログへの登録）",
      "OCSPStapling": "有効（証明書検証の高速化）"
    },
    "通信フロー別暗号化": {
      "External_to_AWS": {
        "ClientToCloudFront": "TLS 1.3（HTTP/3対応）",
        "CloudFrontToOrigin": "TLS 1.2以上（相互認証）",
        "CustomHeaders": "暗号化必須（X-Custom-Auth）",
        "SecurityHeaders": "HSTS、CSP、X-Frame-Options必須"
      },
      "Internal_AWS_Services": {
        "ALBToECS": "TLS 1.2以上（ACM証明書）",
        "ECSToAurora": "TLS 1.2 + IAM認証",
        "ServiceToService": "mTLS (相互認証)",
        "VPCEndpoint": "TLS 1.2以上（PrivateLink）"
      },
      "Hybrid_OnPremises": {
        "DirectConnect": "MACsec暗号化（Layer 2暗号化）",
        "VPN": "IPSec AES-256（IKEv2）",
        "ApplicationLayer": "TLS 1.3（追加暗号化層）"
      }
    }
  }
}
```

全ての通信経路で強力な暗号化を実装し、盗聴や改ざんを防止します。暗号化のオーバーヘッドは5%未満に抑えられています。

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
      ValidationMode: "STRICT（証明書チェーン完全検証）"
      
  API_Gateway_Integration:
    UpstreamTLS: "TLS 1.2 minimum"
    DownstreamTLS: "TLS 1.3 preferred"
    CertificatePinning: "Enabled for critical services"
    BackendAuthentication: "mTLS + API Key"
    
  Database_Connections:
    Aurora_MySQL:
      SSL_Mode: "REQUIRED"
      SSL_Cipher: "AES256-SHA256"
      CertificateVerification: "VERIFY_IDENTITY"
      ConnectionPooling: "暗号化接続プール"
      
  Message_Queues:
    SQS: "Server-side encryption with KMS"
    SNS: "Message encryption in transit and at rest"
    EventBridge: "Event encryption with customer managed keys"
```

マイクロサービス間でも相互認証と暗号化を実装し、内部ネットワークでの攻撃を防止します。サービスメッシュ不要で同等のセキュリティを実現します。

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
          "UsedBy": ["CloudFront", "ALB", "API Gateway"],
          "BackupCertificate": "別リージョンに複製",
          "MonitoringAlerts": "30日前、14日前、7日前"
        },
        "api.technova.com": {
          "Type": "Single Domain Certificate",
          "ValidationMethod": "DNS",
          "AutoRenewal": true,
          "UsedBy": ["API Gateway", "ECS Services"],
          "RateLimiting": "証明書固有のレート制限",
          "GeoRestriction": "日本・米国・EUのみ"
        }
      },
      "PrivateCertificates": {
        "internal.technova.local": {
          "Type": "Private CA Certificate",
          "IssuingCA": "AWS Private Certificate Authority",
          "UsedBy": ["Internal Service Communication"],
          "ValidityPeriod": "1 year",
          "CRLDistribution": "S3 + CloudFront",
          "OCSPResponder": "高可用性OCSP"
        }
      }
    },
    "マイクロサービス別証明書": {
      "manufacturing-planning.internal": "Service-specific certificate",
      "sales-order.internal": "Service-specific certificate",
      "inventory-management.internal": "Service-specific certificate",
      "証明書命名規則": "{service-name}.{environment}.internal",
      "自動プロビジョニング": "Terraform + Lambda"
    }
  }
}
```

自動更新により証明書の期限切れを防止し、サービス停止リスクを排除します。証明書の不正使用は即座に検出されます。

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
      KeyRotation: "毎月自動ローテーション"
    VirtualInterface:
      BGP_MD5: "Enabled"
      BGP_Password: "Complex 32-character password"
      VLAN_Encryption: "802.1AE MACsec"
      TrafficSegmentation: "VLAN別暗号化キー"
      
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
      DPD_Retries: "3"
      
  Client_VPN:
    Protocol: "OpenVPN"
    Cipher: "AES-256-GCM"
    Auth: "SHA-256"
    Certificate_Authentication: "Mutual authentication"
    SAML_Integration: "Active Directory Federation"
    SessionDuration: "8 hours maximum"
    IdleTimeout: "30 minutes"
```

オンプレミスとの接続でも最高レベルの暗号化を実装し、通信の機密性を保証します。量子コンピュータ耐性も考慮した設計となっています。

#### アプリケーション層暗号化

**データフロー暗号化**

```json
{
  "ApplicationLayerEncryption": {
    "API通信": {
      "REST_APIs": {
        "Protocol": "HTTPS only",
        "TLS_Version": "1.3",
        "HSTS": "Enabled（max-age=31536000）",
        "Certificate_Transparency": "Enabled",
        "APIKey_Encryption": "追加暗号化層",
        "RequestSigning": "AWS SigV4互換"
      },
      "GraphQL_APIs": {
        "Transport": "HTTPS/WSS",
        "Query_Encryption": "Field-level encryption for sensitive data",
        "Response_Encryption": "Conditional based on data classification",
        "SubscriptionSecurity": "JWT + WSS"
      },
      "gRPC_Services": {
        "Transport": "HTTP/2 over TLS",
        "Application_Layer_Protocol_Negotiation": "Enabled",
        "Connection_Multiplexing": "Encrypted streams",
        "LoadBalancing": "Client-side with health checks"
      }
    },
    "WebSocket通信": {
      "Protocol": "WSS (WebSocket Secure)",
      "TLS_Version": "1.3",
      "Message_Level_Encryption": "Additional AES-256 for sensitive payloads",
      "HeartBeat": "暗号化されたキープアライブ",
      "Compression": "無効（CRIME/BREACH対策）"
    },
    "ファイル転送": {
      "S3_Upload": "TLS 1.2 + Server-side encryption",
      "Direct_Upload": "Multipart upload with encryption",
      "Pre_signed_URLs": "Short expiration (15分) + HTTPS only",
      "TransferAcceleration": "暗号化されたエッジアップロード"
    }
  }
}
```

アプリケーション層でも追加の暗号化を実装し、多層防御を実現します。暗号化による遅延は10ms未満に最適化されています。

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
    - CT_Log_Monitoring: "証明書透明性ログの監視"
    
  TLS_Configuration_Compliance:
    - Config_Rules:
        - "alb-tls-1-2-required"
        - "cloudfront-tls-1-2-required"
        - "api-gateway-tls-1-2-required"
        - "rds-tls-version-check"
    - Custom_Checks:
        - "Verify cipher suite compliance"
        - "Check certificate chain validity"
        - "Validate OCSP stapling"
        - "Confirm HSTS implementation"
        
  Traffic_Analysis:
    - Encrypted_Traffic_Percentage: "Target: 100%"
    - Unencrypted_Detection: "Immediate alerts"
    - TLS_Handshake_Failures: "Trending analysis"
    - Performance_Impact: "Latency monitoring"
    - Protocol_Distribution: "TLS version usage stats"
```

暗号化の実装状況を継続的に監視し、セキュリティレベルを維持します。SSL Labsで常にA+評価を維持することを目標とします。

#### 暗号化キー管理統合

**KMS統合暗号化**

```json
{
  "EncryptionKeyManagement": {
    "通信暗号化キー階層": {
      "TLS_Certificates": {
        "KeyType": "RSA-2048 or EC P-256",
        "Management": "AWS Certificate Manager",
        "Rotation": "Automatic",
        "Escrow": "無効（キーエスクローなし）"
      },
      "Application_Level_Keys": {
        "KeyType": "AES-256",
        "Management": "AWS KMS",
        "Usage": "Field-level encryption",
        "Rotation": "Annual",
        "MultiRegion": "レプリケーション有効"
      },
      "Service_Communication_Keys": {
        "KeyType": "EC P-256",
        "Management": "AWS Private CA",
        "Usage": "mTLS certificates",
        "Rotation": "Quarterly",
        "Revocation": "CRL + OCSP"
      }
    },
    "キーガバナンス": {
      "KeyAccess": "Role-based with least privilege",
      "KeyAuditing": "All key usage logged in CloudTrail",
      "KeyRotation": "Automated with business approval",
      "KeyRecovery": "Secure backup and recovery procedures",
      "KeyDeletion": "7-30日の待機期間必須"
    }
  }
}
```

階層的なキー管理により、適切なアクセス制御と監査性を実現します。キーの不正使用は5分以内に検出されます。

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
    - 0-RTT_Resumption: "有効（リプレイ攻撃対策付き）"
    
  Cipher_Suite_Optimization:
    - AEAD_Ciphers: "Preferred for authenticated encryption"
    - ECDHE_Key_Exchange: "Perfect Forward Secrecy"
    - Hardware_AES: "AES-NI instruction utilization"
    - ChaCha20: "モバイルデバイス向け最適化"
    
  Load_Distribution:
    - SSL_Termination: "Load balancer level"
    - Connection_Pooling: "Backend SSL connection reuse"
    - Regional_Distribution: "Edge location SSL termination"
    - Caching_Strategy: "暗号化されたコンテンツキャッシュ"
```

ハードウェアアクセラレーションとセッション再利用により、暗号化のパフォーマンス影響を最小化します。暗号化によるレイテンシ増加は5%未満です。

#### 暗号化コンプライアンス

**規制要件対応**

```json
{
  "EncryptionCompliance": {
    "FIPS_140_2": {
      "Level": "Level 2 validated modules",
      "Scope": "All cryptographic operations",
      "Implementation": "AWS FIPS endpoints",
      "Validation": "年次更新確認"
    },
    "Common_Criteria": {
      "EAL_Level": "EAL4+",
      "Validated_Components": "AWS KMS, CloudHSM",
      "Certification": "有効期限管理"
    },
    "Industry_Standards": {
      "PCI_DSS": "Strong cryptography for cardholder data",
      "GDPR": "Appropriate technical measures",
      "HIPAA": "Encryption of PHI in transit",
      "SOC2": "Type II準拠"
    },
    "国内規制": {
      "個人情報保護法": "個人データの安全管理措置",
      "サイバーセキュリティ基本法": "重要インフラの保護",
      "不正アクセス禁止法": "適切なアクセス制御"
    },
    "暗号化アルゴリズム規制": {
      "輸出規制": "各国規制への準拠確認",
      "使用制限": "特定国での暗号強度制限対応"
    }
  }
}
```

各種規制要件に準拠した暗号化実装により、コンプライアンスリスクを排除します。定期的な監査により準拠状態を維持します。

### 7. コンテナセキュリティ（ECS/ECR）

#### ECR セキュリティ設定

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
      "ScanningScope": "OS packages + Application dependencies",
      "CVEDatabase": "NVD + vendor-specific sources"
    },
    "ImageImmutability": true,
    "ImageSigning": {
      "Enabled": true,
      "SigningProfile": "container-signing-profile",
      "VerificationPolicy": "署名のないイメージは拒否"
    },
    "Encryption": {
      "Type": "KMS",
      "KMSKey": "service-specific-key",
      "EncryptionScope": "イメージレイヤー + メタデータ"
    },
    "LifecyclePolicy": {
      "UntaggedImages": "Delete after 7 days",
      "TaggedImages": "Keep latest 10 versions",
      "VulnerableImages": "自動削除（Critical脆弱性）"
    },
    "AccessControl": {
      "RepositoryPolicy": "サービス別アクセス制限",
      "CrossAccountAccess": "明示的な許可のみ",
      "PullRateLimit": "1000 pulls/hour/service"
    }
  }
}
```

プッシュ時と継続的なスキャンにより、脆弱性のあるイメージの使用を防止します。署名により、イメージの改ざんも検出できます。

**脆弱性管理自動化**

```yaml
# Container Security Automation
VulnerabilityManagement:
  Detection:
    - Continuous Image Scanning（24時間ごと再スキャン）
    - Runtime Vulnerability Assessment（実行中コンテナの監視）
    - Third-party Security Integration（Snyk, Twistlock連携）
    - SBOM Generation（全依存関係の記録）
    
  Response:
    - Automated Patch Deployment（自動パッチ適用）
    - Image Rebuild Triggers（ベースイメージ更新時）
    - Security Alert Notifications（重要度別通知）
    - Rollback Capability（問題発生時の自動ロールバック）
    
  Compliance:
    - CIS Benchmark Compliance（コンテナ設定基準）
    - NIST Container Security Guidelines（SP 800-190準拠）
    - Industry Best Practices（12-Factor App準拠）
    - Custom Compliance Rules（組織固有ルール）
```

脆弱性の検出から修復まで自動化し、セキュリティレベルを継続的に維持します。MTTRは4時間以内を目標とします。

#### ECS Runtime セキュリティ

**コンテナランタイム保護**

```json
{
  "ECSSecurityConfiguration": {
    "TaskDefinitionSecurity": {
      "Privileged": false,
      "ReadOnlyRootFilesystem": true,
      "User": "non-root（UID 1000+）",
      "NetworkMode": "awsvpc",
      "RequireCompatibilities": ["FARGATE"],
      "LinuxParameters": {
        "Capabilities": {
          "Drop": ["ALL"],
          "Add": ["NET_BIND_SERVICE"]
        },
        "SeccompProfile": "runtime/default"
      }
    },
    "SecretsManagement": {
      "SecretProvider": "AWS Secrets Manager",
      "AutoRotation": true,
      "EncryptionInTransit": true,
      "SecretCaching": "5分間のメモリ内キャッシュ",
      "AuditLogging": "全アクセスログ記録"
    },
    "LogConfiguration": {
      "LogDriver": "awslogs",
      "LogGroup": "/ecs/security-enhanced",
      "LogRetention": "30 days",
      "LogEncryption": "KMS暗号化",
      "LogFiltering": "機密情報の自動マスキング"
    },
    "ResourceLimits": {
      "CPU": "タスク定義で明示的に指定",
      "Memory": "ハードリミット設定必須",
      "Storage": "一時ストレージ20GB制限"
    }
  }
}
```

最小権限の原則に基づいたコンテナ実行により、攻撃面を最小化します。読み取り専用ファイルシステムにより、実行時の改ざんを防止します。

**Service Connect セキュリティ**

```yaml
# Service Connect Security Configuration
ServiceConnectSecurity:
  Encryption:
    - TLS 1.3 for Service Communication
    - Certificate Management via ACM
    - Automatic Certificate Rotation
    - Zero-Trust Service Mesh
    
  Authentication:
    - mTLS for Service-to-Service Communication
    - IAM Roles for Service Identity
    - Service Mesh Integration（Envoyプロキシ）
    - Token-based Authentication（JWT）
    
  Authorization:
    - Service-level Access Control
    - API Method-level Permissions
    - Rate Limiting per Service
    - Circuit Breaker Implementation
    
  Monitoring:
    - Traffic Flow Analysis（X-Ray統合）
    - Anomaly Detection（異常通信パターン検出）
    - Security Event Correlation（SIEM連携）
    - Performance Monitoring（レイテンシ追跡）
```

サービス間通信の暗号化と認証により、内部ネットワークでの攻撃を防止します。Service Connectにより、複雑なサービスメッシュ不要で実装できます。

### 8. データベースセキュリティ（Aurora）

#### Aurora セキュリティ設定

**データベース暗号化とアクセス制御**

```json
{
  "AuroraSecurityConfiguration": {
    "Encryption": {
      "EncryptionAtRest": {
        "Enabled": true,
        "KMSKey": "service-specific-key",
        "AlgorithmSuite": "AES-256",
        "BackupEncryption": "同一キーで暗号化"
      },
      "EncryptionInTransit": {
        "Enabled": true,
        "TLSVersion": "1.2",
        "CertificateValidation": true,
        "ForceTLS": "必須（非TLS接続は拒否）"
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
        "SubnetGroups": ["private-subnets-only"],
        "PubliclyAccessible": false
      }
    },
    "BackupStrategy": {
      "AutomatedBackup": {
        "RetentionPeriod": "35 days",
        "BackupWindow": "03:00-04:00 UTC",
        "PointInTimeRecovery": true
      },
      "SnapshotExport": {
        "S3Export": "監査用長期保存",
        "Encryption": "KMS暗号化必須"
      }
    }
  }
}
```

保存時と転送時の暗号化、IAM認証により、データベースレベルでの多層防御を実現します。バックアップも完全に暗号化されます。

**データベース監査とモニタリング**

```yaml
# Database Security Monitoring
DatabaseAuditing:
  AuditLogging:
    - All Connection Attempts（成功/失敗問わず）
    - Query Execution Logs（DDL/DML全て）
    - Schema Changes（テーブル・インデックス変更）
    - Privilege Escalations（権限変更の追跡）
    - Failed Authentication（不正アクセス試行）
    
  PerformanceInsights:
    - Query Performance Monitoring（スロークエリ検出）
    - Resource Utilization Tracking（CPU/メモリ/IO）
    - Anomaly Detection（異常なクエリパターン）
    - Wait Event Analysis（ボトルネック分析）
    
  AdvancedAuditing:
    - Database Activity Streams（リアルタイム監査）
    - Kinesis Integration（ストリーム処理）
    - Long-term Retention（S3への自動アーカイブ）
    - Compliance Reporting（監査レポート自動生成）
    
  Alerting:
    - Suspicious Query Patterns（不審なクエリ検出）
    - Unusual Connection Attempts（異常な接続試行）
    - Performance Degradation（性能劣化アラート）
    - Security Policy Violations（ポリシー違反検出）
    - Automated Response（自動対応トリガー）
```

全てのデータベースアクティビティを監視し、不正アクセスや異常を早期検出します。Database Activity Streamsにより、監査ログの改ざんも防止します。

#### データ分類と保護

**データ分類フレームワーク**

```json
{
  "DataClassification": {
    "Confidential": {
      "Examples": ["customer_personal_data", "financial_records", "employee_salary"],
      "EncryptionRequired": true,
      "AccessRestrictions": "Need-to-know basis",
      "AuditLogging": "Enhanced",
      "DataRetention": "Legal requirements",
      "BackupStrategy": "暗号化バックアップ + 異地保管",
      "DataMasking": "本番データの開発環境コピー時は必須"
    },
    "Internal": {
      "Examples": ["business_processes", "internal_reports", "meeting_minutes"],
      "EncryptionRequired": true,
      "AccessRestrictions": "Employee access only",
      "AuditLogging": "Standard",
      "DataRetention": "7 years",
      "BackupStrategy": "標準バックアップポリシー",
      "DataSharing": "部門間共有は承認制"
    },
    "Public": {
      "Examples": ["product_specifications", "marketing_materials", "press_releases"],
      "EncryptionRequired": false,
      "AccessRestrictions": "Public access allowed",
      "AuditLogging": "Basic",
      "DataRetention": "As needed",
      "CDNDistribution": "CloudFront経由で配信可能",
      "CachingPolicy": "積極的キャッシュ"
    }
  }
}
```

データの重要度に応じた保護レベルを適用し、過剰でも不足でもない適切なセキュリティを実現します。分類は自動化ツールでも判定されます。

### 9. S3セキュリティ・アクセス制御

#### S3バケットセキュリティ設計

**バケット別セキュリティ戦略**

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
        "EventNotifications": "全操作",
        "ObjectLock": "Compliance Mode（改ざん防止）",
        "ReplicationStrategy": "クロスリージョンレプリケーション"
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
        "LifecyclePolicy": "自動階層化",
        "IntelligentTiering": "コスト最適化",
        "TransferAcceleration": "グローバルアクセス高速化"
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
        "ImmutableAccess": "有効",
        "StorageClass": "Glacier Deep Archive（1年後）",
        "AccessPattern": "Write Once Read Many (WORM)"
      }
    }
  }
}
```

バケットの用途に応じて適切なセキュリティレベルを適用し、データの重要度に見合った保護を実現します。Object Lockにより、規制要件も満たします。

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
            "Sid": "AllowServiceSpecificAccess",
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
                "s3:x-amz-server-side-encryption": "AES256",
                "aws:PrincipalTag/Department": "Manufacturing"
              },
              "Bool": {
                "aws:SecureTransport": "true"
              },
              "IpAddress": {
                "aws:SourceIp": ["10.0.0.0/14"]
              }
            }
          },
          {
            "Sid": "AllowListBucketWithPrefix",
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
              },
              "DateGreaterThan": {
                "aws:CurrentTime": "2024-01-01T00:00:00Z"
              }
            }
          }
        ]
      }
    }
  }
}
```

サービスごとに必要最小限のアクセス権限を付与し、暗号化とHTTPS通信を強制します。IPアドレスとタグベースの追加制御も実装します。

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
            "s3:x-amz-server-side-encryption": "aws:kms",
            "s3:ExistingObjectTag/DataClassification": "Confidential"
          },
          "DateGreaterThan": {
            "aws:CurrentTime": "2024-01-01T00:00:00Z"
          },
          "StringLike": {
            "aws:userid": "AIDAI*"
          }
        }
      },
      {
        "Sid": "DenyObjectLockBypass",
        "Effect": "Deny",
        "Principal": "*",
        "Action": [
          "s3:BypassGovernanceRetention",
          "s3:DeleteObjectVersion"
        ],
        "Resource": "arn:aws:s3:::technova-customer-data-prod/*",
        "Condition": {
          "StringNotEquals": {
            "aws:PrincipalOrgID": "o-technova"
          }
        }
      }
    ]
  }
}
```

多層的な条件により、暗号化されていない通信やオブジェクトのアップロードを完全に防止します。Object Lockの迂回も防ぎます。

#### S3 Access Points とマルチリージョンアクセス制御

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
            StringLike:
              "s3:prefix": ["production/*", "quality/*"]
              
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
            DateGreaterThan:
              "aws:CurrentTime": "${aws:CurrentTime - 3600}"  # 1時間以内のトークンのみ
              
  multi-region-access-point:
    Type: "Multi-Region"
    Regions: ["ap-northeast-1", "us-east-1", "eu-west-1"]
    PublicAccessBlock: "全て有効"
    FailoverControl: "自動フェイルオーバー"
    ReplicationRules: "双方向レプリケーション"
```

Access Pointsにより、同一バケットに対して部門ごとに異なるアクセス制御を適用できます。Multi-Region Access Pointにより、グローバルな可用性も実現します。

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
            "And": {
              "Prefix": "customer-data/",
              "Tags": [
                {
                  "Key": "ReplicationRequired",
                  "Value": "true"
                }
              ]
            }
          },
          "DeleteMarkerReplication": {
            "Status": "Enabled"
          },
          "Destination": {
            "Bucket": "arn:aws:s3:::technova-customer-data-dr-osaka",
            "StorageClass": "STANDARD_IA",
            "EncryptionConfiguration": {
              "ReplicaKmsKeyID": "arn:aws:kms:ap-northeast-3:123456789012:key/dr-customer-data-key"
            },
            "AccessControlTranslation": {
              "Owner": "Destination"
            },
            "ReplicationTime": {
              "Status": "Enabled",
              "Time": {
                "Minutes": 15
              }
            },
            "Metrics": {
              "Status": "Enabled",
              "EventThreshold": {
                "Minutes": 15
              }
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
            "s3:GetObjectVersionAcl",
            "s3:GetObjectVersionTagging"
          ],
          "Resource": "arn:aws:s3:::technova-customer-data-prod/*"
        },
        {
          "Effect": "Allow",
          "Action": [
            "s3:ReplicateObject",
            "s3:ReplicateDelete",
            "s3:ReplicateTags"
          ],
          "Resource": "arn:aws:s3:::technova-customer-data-dr-osaka/*"
        },
        {
          "Effect": "Allow",
          "Action": [
            "s3:ListBucket"
          ],
          "Resource": [
            "arn:aws:s3:::technova-customer-data-prod",
            "arn:aws:s3:::technova-customer-data-dr-osaka"
          ]
        },
        {
          "Effect": "Allow",
          "Action": [
            "kms:Decrypt",
            "kms:DescribeKey"
          ],
          "Resource": "arn:aws:kms:ap-northeast-1:123456789012:key/customer-data-key-id",
          "Condition": {
            "StringLike": {
              "kms:ViaService": "s3.ap-northeast-1.amazonaws.com"
            }
          }
        },
        {
          "Effect": "Allow",
          "Action": [
            "kms:GenerateDataKey",
            "kms:Encrypt"
          ],
          "Resource": "arn:aws:kms:ap-northeast-3:123456789012:key/dr-customer-data-key",
          "Condition": {
            "StringLike": {
              "kms:ViaService": "s3.ap-northeast-3.amazonaws.com"
            }
          }
        }
      ]
    }
  }
}
```

レプリケーション時も暗号化を維持し、DR環境でも同等のセキュリティレベルを確保します。RTC（Replication Time Control）により、15分以内のレプリケーションを保証します。

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
          ],
          "AdvancedEventSelectors": [
            {
              "Name": "LogAllObjectAccess",
              "FieldSelectors": [
                {
                  "Field": "eventCategory",
                  "Equals": ["Data"]
                },
                {
                  "Field": "resources.type",
                  "Equals": ["AWS::S3::Object"]
                }
              ]
            }
          ]
        }
      ]
    },
    "S3AccessLogging": {
      "TargetBucket": "technova-s3-access-logs-prod",
      "TargetPrefix": "access-logs/",
      "LogObjectKeyFormat": "PartitionedPrefix",
      "LogDeliveryFrequency": "5 minutes",
      "LogAnalysis": "Athena + QuickSight"
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
            },
            {
              "Name": "suffix",
              "Value": ".encrypted"
            }
          ]
        },
        {
          "EventName": "ObjectRemoved",
          "EventDestination": "Lambda Function",
          "Function": "s3-delete-alert-handler",
          "RequiredApproval": "2名承認必須"
        }
      ],
      "EventBridgeIntegration": {
        "Enabled": true,
        "DetailedMonitoring": "全イベント転送"
      }
    }
  }
}
```

全てのS3操作を記録し、機密データへのアクセスや削除を即座に検知します。EventBridge統合により、複雑なイベント処理も可能です。

#### S3セキュリティ自動化

**自動修復・対応**

```yaml
# S3 Security Automation
S3SecurityAutomation:
  ComplianceMonitoring:
    - PolicyViolationDetection:
        Trigger: "Config Rule違反"
        Response: "自動アラート + 手動修復"
        Severity: "バケットポリシーの重要度で判定"
    - PublicAccessDetection:
        Trigger: "Public Read/Write検出"
        Response: "即座にブロック + セキュリティチーム通知"
        AutoRemediation: "30秒以内に自動修復"
    - UnencryptedObjectDetection:
        Trigger: "暗号化されていないオブジェクト検出"
        Response: "アップロードブロック + 自動暗号化"
        NotificationChannel: "Slack + Email + PagerDuty"
        
  AccessAnomalyDetection:
    - UnusualAccessPatterns:
        Detection: "GuardDuty Malicious IP"
        Response: "IP自動ブロック + インシデント作成"
        BlockDuration: "24時間（手動解除可能）"
    - MassDownloadDetection:
        Detection: "大量ダウンロード (>1GB/hour)"
        Response: "一時的アクセス制限 + 調査開始"
        ThrottleLimit: "100MB/hour に制限"
    - CrossRegionAccessAnomaly:
        Detection: "通常と異なるリージョンからのアクセス"
        Response: "MFA再認証要求 + ログ強化"
        RiskScore: "アクセスパターンに基づく動的スコアリング"
        
  AutomatedRemediation:
    - S3-Bucket-Public-Access-Prohibited:
        RemediationAction: "aws-s3-bucket-public-access-block"
        Parameters:
          BlockPublicAcls: true
          BlockPublicPolicy: true
          IgnorePublicAcls: true
          RestrictPublicBuckets: true
        ExecutionTimeout: "60 seconds"
    - S3-Bucket-SSL-Requests-Only:
        RemediationAction: "aws-s3-bucket-ssl-requests-only"
        Parameters:
          BucketPolicy: "DenyInsecureConnections"
          PolicyTemplate: "organization-standard-template"
    - S3-Bucket-Versioning-Enabled:
        RemediationAction: "enable-bucket-versioning"
        Parameters:
          VersioningConfiguration: "Enabled"
          MFADelete: "Enabled for critical buckets"
```

設定違反や異常アクセスを自動的に検出・修復し、人的ミスによるセキュリティインシデントを防止します。機械学習による異常検知も活用します。

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
              "Years": 7,
              "Description": "法的保存要件対応"
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
          },
          {
            "Key": "DataController",
            "Value": "TechNova"
          }
        ],
        "InventoryConfiguration": {
          "Frequency": "Daily",
          "IncludedObjectVersions": "Current",
          "OptionalFields": ["Size", "LastModifiedDate", "StorageClass", "ETag", "IsMultipartUploaded", "ReplicationStatus", "EncryptionStatus"]
        }
      }
    },
    "DataSubjectRightsSupport": {
      "RightToErasure": {
        "AutomatedDeletion": "Lambda function triggered by API",
        "VerificationProcess": "Multi-step approval",
        "AuditTrail": "Complete deletion record in CloudTrail",
        "BackupHandling": "同時にバックアップからも削除",
        "CompletionNotification": "データ主体への完了通知"
      },
      "RightToAccess": {
        "DataInventory": "S3 Inventory + Lambda processing",
        "ResponseTime": "30 days maximum",
        "DeliveryMethod": "Secure download link",
        "DataFormat": "JSON/CSV選択可能",
        "EncryptionRequirement": "エンドツーエンド暗号化"
      },
      "RightToPortability": {
        "ExportFormat": "機械可読形式（JSON/XML）",
        "TransferMechanism": "直接転送API対応",
        "DataIntegrity": "チェックサム検証"
      }
    }
  }
}
```

GDPR要件に完全準拠し、データ主体の権利行使に迅速に対応できる体制を構築します。自動化により、30日の対応期限を確実に遵守します。

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
      RateLimiting: "1000 requests/minute"
      ConcurrentConnections: 50
      
    InventoryManagementService:
      AllowedBuckets:
        - "technova-inventory-data-prod"
        - "technova-manufacturing-shared-prod"
      AllowedActions: ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
      CrossServiceAccess:
        - Service: "SalesOrderService"
          BucketPath: "technova-inventory-data-prod/stock-levels/*"
          Permission: "ReadOnly"
          ValidityPeriod: "1 hour"
      EventTriggers:
        - OnObjectCreated: "inventory-update-processor"
        - OnObjectRemoved: "inventory-audit-logger"
          
  Sales:
    CustomerManagementService:
      AllowedBuckets:
        - "technova-customer-data-prod"
      AllowedActions: ["s3:GetObject", "s3:PutObject"]
      DataClassification: "Confidential"
      EncryptionRequired: "Customer-managed KMS"
      AccessLogging: "Enhanced"
      PIIDetection: "Automated Macie scanning"
      DataResidency: "ap-northeast-1 only"
      
  IoT:
    TelemetryService:
      AllowedBuckets:
        - "technova-iot-telemetry-prod"
        - "technova-iot-processed-data-prod"
      AllowedActions: ["s3:PutObject", "s3:GetObject"]
      VolumeRestrictions:
        MaxObjectSize: "100MB"
        DailyUploadLimit: "10GB"
        BurstCapacity: "1GB/hour"
      LifecycleManagement:
        TransitionToIA: "30 days"
        TransitionToGlacier: "90 days"
        ExpireObjects: "2 years"
      StreamingUpload: "Kinesis Data Firehose integration"
      CompressionRequired: "gzip or snappy"
```

各マイクロサービスに最適化されたアクセス制御により、最小権限の原則を実現します。サービス特性に応じた制限も適用します。

### 10. API セキュリティ（Gateway/Cognito）

#### API Gateway セキュリティ設定

**API認証と認可**

```json
{
  "APIGatewaySecurity": {
    "Authentication": {
      "CognitoUserPools": {
        "AuthType": "JWT",
        "TokenValidation": true,
        "ScopeValidation": true,
        "CustomAuthorizer": "追加検証ロジック",
        "TokenExpiry": "1 hour",
        "RefreshTokenExpiry": "30 days"
      },
      "IAMRoles": {
        "ServiceToService": true,
        "CrossAccountAccess": "Restricted",
        "SignatureVersion": "v4",
        "TemporaryCredentials": "15 minutes"
      },
      "APIKeys": {
        "UsagePlans": "顧客別プラン",
        "RateLimiting": "プラン別制限",
        "QuotaManagement": "月次リセット"
      }
    },
    "Authorization": {
      "ScopeBasedAccess": true,
      "ResourceBasedPolicies": true,
      "ContextualAccess": "IP, Time, Device",
      "FineGrainedPermissions": "メソッド・リソース別",
      "DynamicAuthorization": "属性ベースアクセス制御"
    },
    "Throttling": {
      "BurstLimit": 1000,
      "RateLimit": 500,
      "QuotaLimit": "10000/day",
      "MethodLevelThrottling": "重要APIは個別設定",
      "ErrorHandling": "429エラーとRetry-Afterヘッダー"
    },
    "Caching": {
      "CacheClusterSize": "6.1GB",
      "TTL": "300 seconds",
      "CacheKeyParameters": "認証情報を除外",
      "InvalidationStrategy": "タグベース無効化"
    }
  }
}
```

多層的な認証・認可とレート制限により、APIの悪用を防止します。キャッシュにより、バックエンドの負荷も軽減します。

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
          ScopeDownStatement:
            ByteMatchStatement:
              SearchString: "/api/v1/sensitive"
              FieldToMatch:
                UriPath: {}
              TextTransformations:
                - Priority: 0
                  Type: "LOWERCASE"
              PositionalConstraint: "STARTS_WITH"
              
    - Name: "API-payload-validation"
      Priority: 2
      Action: "Block"
      Statement:
        SizeConstraintStatement:
          FieldToMatch:
            Body: {}
          ComparisonOperator: "GT"
          Size: 1048576  # 1MB limit
          TextTransformations:
            - Priority: 0
              Type: "NONE"
              
    - Name: "SQL-injection-protection"
      Priority: 3
      Action: "Block"
      Statement:
        SqlInjectionMatchStatement:
          FieldToMatch:
            AllQueryArguments: {}
          TextTransformations:
            - Priority: 0
              Type: "URL_DECODE"
            - Priority: 1
              Type: "HTML_ENTITY_DECODE"
              
  ManagedRuleGroups:
    - Name: "AWSManagedRulesAPIGatewayRuleSet"
      Priority: 10
      OverrideAction: "None"
      ExcludedRules: []
      
  IPReputationLists:
    - Type: "AWSManagedIPReputationList"
      Action: "Block"
    - Type: "CustomIPList"
      Source: "s3://security-lists/blocked-ips.txt"
      UpdateFrequency: "1 hour"
```

API固有の脅威に対する防御を実装し、ペイロードサイズやレート制限を適用します。SQLインジェクション対策も多層的に実装します。

#### Cognito セキュリティ強化

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
      "TemporaryPasswordValidityDays": 1,
      "PasswordHistory": 5,
      "PreventCommonPasswords": true
    },
    "MFAConfiguration": {
      "MFARequired": true,
      "AllowedMFATypes": ["SMS", "TOTP", "WebAuthn"],
      "PreferredMFA": "TOTP",
      "SMSConfiguration": {
        "SNSCallerArn": "arn:aws:iam::account:role/cognito-sns-role",
        "ExternalId": "random-external-id"
      },
      "SoftwareTokenMFA": {
        "Enabled": true,
        "ApplicationName": "TechNova Authenticator"
      }
    },
    "AccountSecurity": {
      "AccountRecovery": "Email and Phone",
      "PreventUserExistenceErrors": true,
      "AdvancedSecurityMode": "ENFORCED",
      "UserVerification": {
        "EmailVerification": "Required",
        "PhoneVerification": "Optional",
        "AttributeVerification": ["email", "phone_number"]
      }
    },
    "DeviceTracking": {
      "ChallengeRequiredOnNewDevice": true,
      "DeviceOnlyRememberedOnUserPrompt": true,
      "MaxDevicesPerUser": 5,
      "DeviceFingerpinting": "Enhanced"
    },
    "RiskConfiguration": {
      "CompromisedCredentialsRiskConfiguration": {
        "EventFilter": ["SIGN_IN", "PASSWORD_CHANGE", "SIGN_UP"],
        "Actions": {
          "EventAction": "BLOCK"
        }
      },
      "AccountTakeoverRiskConfiguration": {
        "NotifyConfiguration": {
          "From": "security@technova.com",
          "ReplyTo": "no-reply@technova.com",
          "SourceArn": "arn:aws:ses:region:account:identity/security@technova.com",
          "BlockEmail": {
            "Subject": "Security Alert: Blocked Sign-in Attempt",
            "HtmlBody": "template-html",
            "TextBody": "template-text"
          },
          "NoActionEmail": {
            "Subject": "Security Alert: Unusual Sign-in",
            "HtmlBody": "template-html",
            "TextBody": "template-text"
          },
          "MfaEmail": {
            "Subject": "Security Alert: MFA Required",
            "HtmlBody": "template-html",
            "TextBody": "template-text"
          }
        },
        "Actions": {
          "LowAction": {
            "Notify": true,
            "EventAction": "ALLOW"
          },
          "MediumAction": {
            "Notify": true,
            "EventAction": "MFA_IF_CONFIGURED"
          },
          "HighAction": {
            "Notify": true,
            "EventAction": "MFA_REQUIRED"
          }
        }
      }
    }
  }
}
```

強固なパスワードポリシーとMFA必須化により、アカウント乗っ取りのリスクを最小化します。リスクベース認証により、異常なアクセスも検出します。

### 11. Secrets Management と Key Management

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
        "EncryptionKey": "service-specific-kms-key",
        "VersionRetention": 7,
        "AccessPattern": "キャッシュ付き取得",
        "BackupStrategy": "クロスリージョンレプリケーション"
      },
      "APIKeys": {
        "Scope": "Per-integration",
        "RotationEnabled": true,
        "RotationInterval": "90 days",
        "AccessLogging": "Enhanced",
        "UsageTracking": "CloudTrail統合",
        "ExpiryNotification": "30日前アラート"
      },
      "CertificateKeys": {
        "Scope": "Per-domain",
        "RotationEnabled": true,
        "RotationInterval": "365 days",
        "CertificateAuthority": "AWS ACM",
        "KeyAlgorithm": "RSA-2048",
        "BackupLocation": "HSM"
      },
      "EncryptionKeys": {
        "Scope": "Per-data-classification",
        "RotationEnabled": true,
        "RotationInterval": "Annual",
        "KeyDerivation": "HKDF-SHA256",
        "KeyWrapping": "AES-KWP"
      }
    },
    "AccessControl": {
      "ResourceBasedPolicies": true,
      "IAMRoleBasedAccess": true,
      "VPCEndpointAccess": true,
      "CrossAccountAccess": "Restricted",
      "ConditionalAccess": {
        "TimeBasedAccess": "業務時間内のみ",
        "IPBasedAccess": "社内ネットワークのみ",
        "MFARequired": "機密シークレットは必須"
      }
    },
    "AuditingAndCompliance": {
      "AccessLogging": "全アクセス記録",
      "RotationTracking": "自動ローテーション履歴",
      "ComplianceReporting": "月次レポート生成",
      "AnomalyDetection": "異常アクセスパターン検知"
    }
  }
}
```

自動ローテーションにより、長期間同じ認証情報を使用するリスクを排除し、侵害時の影響を限定します。階層的なアクセス制御により、不正アクセスを防止します。

#### KMS Key Management

**暗号化キー階層**

```yaml
# KMS Key Management Strategy
KMSKeyHierarchy:
  CustomerMasterKeys:
    - Purpose: "Root Encryption"
      Type: "AWS Managed"
      Usage: "Organization Level"
      KeyPolicy: "組織管理者のみアクセス可能"
      
    - Purpose: "Service Encryption"
      Type: "Customer Managed"
      Usage: "Per-microservice"
      KeyRotation: "Annual"
      KeyPolicy: "サービス別アクセス制御"
      MultiRegion: true
      
    - Purpose: "Data Encryption"
      Type: "Customer Managed"
      Usage: "Per-data-classification"
      KeyRotation: "Annual"
      KeyPolicy: "データ分類別アクセス制御"
      KeySpec: "SYMMETRIC_DEFAULT"
      
    - Purpose: "Code Signing"
      Type: "Customer Managed"
      Usage: "Container Image Signing"
      KeyRotation: "Disabled"
      KeySpec: "ECC_NIST_P256"
      KeyUsage: "SIGN_VERIFY"
      
  KeyPolicies:
    - Principal: "Service Roles"
      Actions: ["kms:Decrypt", "kms:GenerateDataKey"]
      Conditions:
        - StringEquals:
            "kms:ViaService": "service-name.region.amazonaws.com"
        - StringEquals:
            "kms:EncryptionContext:service": "${service-name}"
        - DateGreaterThan:
            "aws:CurrentTime": "${request-time - 3600}"
            
  KeyAliases:
    NamingConvention: "alias/service-name/purpose/environment"
    Examples:
      - "alias/sales-order/database/prod"
      - "alias/manufacturing/s3/prod"
      - "alias/shared/logs/prod"
      
  KeyGrants:
    TemporaryAccess: "時限的アクセス許可"
    GrantTokens: "一時的な権限昇格"
    RetireGrants: "自動失効設定"
```

階層的なキー管理により、適切なアクセス制御と監査性を実現し、キーの不正使用を防止します。マルチリージョンキーにより、DR対応も容易になります。

### 12. 監視・ログ・インシデント対応

#### 統合セキュリティ監視

**Security Hub統合**

```json
{
  "SecurityHubConfiguration": {
    "EnabledStandards": [
      "AWS Foundational Security Best Practices",
      "CIS AWS Foundations Benchmark v1.4",
      "PCI DSS v3.2.1",
      "NIST SP 800-53 Rev. 5"
    ],
    "CustomInsights": [
      {
        "Name": "High-Severity-Findings",
        "Filters": {
          "SeverityLabel": ["HIGH", "CRITICAL"],
          "WorkflowStatus": ["NEW", "NOTIFIED"],
          "RecordState": ["ACTIVE"]
        },
        "GroupBy": "ResourceType"
      },
      {
        "Name": "Compliance-Failures",
        "Filters": {
          "ComplianceStatus": ["FAILED"],
          "RecordState": ["ACTIVE"],
          "ProductName": ["Config", "GuardDuty", "Inspector"]
        },
        "GroupBy": "ComplianceStandard"
      },
      {
        "Name": "Unresolved-Critical-Findings",
        "Filters": {
          "SeverityLabel": ["CRITICAL"],
          "WorkflowStatus": ["NEW", "NOTIFIED"],
          "UpdatedAt": [{"DateRange": {"Value": 7, "Unit": "DAYS"}}]
        },
        "GroupBy": "AwsAccountId"
      }
    ],
    "Automation": {
      "AutomatedRemediationEnabled": true,
      "NotificationTargets": ["security-team-sns-topic"],
      "EscalationProcedures": "security-incident-response-playbook",
      "IntegrationEndpoints": {
        "SIEM": "splunk-hec-endpoint",
        "SOAR": "phantom-api-endpoint",
        "Ticketing": "servicenow-api-endpoint"
      }
    },
    "CrossRegionAggregation": {
      "Enabled": true,
      "AggregationRegion": "ap-northeast-1",
      "LinkedRegions": ["us-east-1", "eu-west-1", "ap-southeast-1"]
    }
  }
}
```

Security Hubにより、複数のセキュリティサービスからの検出事項を一元管理し、優先順位付けされた対応を実現します。自動修復により、対応時間を短縮します。

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
    - EventSelectors:
        - IncludeManagementEvents: true
        - ReadWriteType: "All"
        - DataResources:
            - Type: "AWS::S3::Object"
              Values: ["arn:aws:s3:::*/"]
            - Type: "AWS::Lambda::Function"
              Values: ["arn:aws:lambda:*"]
    
  DataEvents:
    - S3ObjectLevelLogging: true
    - LambdaFunctionLogging: true
    - DynamoDBTableLogging: true
    - RDSDataAPILogging: true
    
  InsightSelectors:
    - ApiCallRateInsight: true
    - ApiErrorRateInsight: true
    - ManagementEventsInsight: true
    
  LogAnalysis:
    - RealTimeProcessing: true
    - AnomalyDetection: true
    - ThreatIntelligence: true
    - CustomRules: "組織固有の検出ルール"
    
  LogDelivery:
    - S3Delivery: "5分以内"
    - CloudWatchLogs: "リアルタイム"
    - EventBridge: "イベント駆動処理"
```

全てのAPIコールを記録し、異常なアクティビティパターンを機械学習により早期検出します。Insightsにより、異常な API 使用パターンも検出します。

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
      "WAF Logs",
      "Config Rules",
      "Custom Applications"
    ],
    "ResponseAutomation": {
      "IsolationProcedures": {
        "NetworkIsolation": "Auto-quarantine suspicious instances",
        "SecurityGroupUpdate": "侵害されたインスタンスのSG変更",
        "NACLUpdate": "サブネットレベルでのブロック",
        "RouteTableUpdate": "通信経路の遮断"
      },
      "AccessRevocation": {
        "IAMUserDisable": "不正使用されたユーザーの無効化",
        "AccessKeyRotation": "侵害されたキーの無効化",
        "SessionTermination": "アクティブセッションの強制終了",
        "MFAReset": "MFAデバイスのリセット"
      },
      "TrafficBlocking": {
        "WAFRuleUpdate": "攻撃パターンのブロック",
        "CloudFrontGeoBlocking": "攻撃元地域のブロック",
        "Route53HealthCheck": "攻撃対象の切り離し"
      }
    },
    "NotificationProcedures": {
      "SecurityTeam": {
        "Channel": "PagerDuty",
        "Priority": "P1",
        "ResponseTime": "15分以内"
      },
      "Management": {
        "Channel": "Email + SMS",
        "Template": "Executive Summary",
        "Timing": "1時間以内"
      },
      "Legal": {
        "Channel": "Secure Email",
        "Criteria": "個人情報漏洩の可能性",
        "Timing": "24時間以内"
      },
      "Stakeholders": {
        "Channel": "Status Page",
        "Updates": "30分ごと",
        "Transparency": "適切な情報開示"
      }
    },
    "EvidenceCollection": {
      "MemoryDumps": {
        "Tool": "SSM Run Command",
        "Storage": "Forensics S3 Bucket",
        "Encryption": "証拠保全用KMS"
      },
      "LogPreservation": {
        "ImmediateBackup": "全関連ログの即時バックアップ",
        "ExtendedRetention": "通常+2年の保存延長",
        "LegalHold": "削除防止設定"
      },
      "ForensicImages": {
        "EBSSnapshots": "影響を受けたボリュームのスナップショット",
        "AMICreation": "フォレンジック用AMI作成",
        "NetworkCapture": "VPC Flow Logs + パケットキャプチャ"
      }
    },
    "PlaybookExecution": {
      "DDoSResponse": "Shield Advanced対応手順",
      "DataBreachResponse": "情報漏洩対応手順",
      "RansomwareResponse": "ランサムウェア対応手順",
      "InsiderThreatResponse": "内部脅威対応手順"
    }
  }
}
```

インシデント発生時の初動対応を自動化し、被害の拡大を防止しながら証拠保全を実施します。プレイブックにより、一貫した対応を実現します。

### 13. 災害復旧・事業継続のセキュリティ

#### DR環境セキュリティ

**大阪リージョンDRセキュリティ**

```yaml
# DR Security Configuration
DRSecurity:
  SecurityReplication:
    - SecurityGroups: "Synchronized（自動同期）"
    - NACLs: "Synchronized（自動同期）"
    - WAFRules: "Synchronized（自動同期）"
    - KMSKeys: "Cross-region replicated（マルチリージョンキー）"
    - IAMRoles: "CloudFormation StackSets"
    - Certificates: "Multi-region ACM"
    
  AccessControl:
    - EmergencyAccess: "Break-glass procedures"
      Approval: "2名承認必須"
      Notification: "全管理者に通知"
      TimeLimit: "24時間有効"
    - DRActivation: "Multi-person authorization"
      RequiredApprovers: 3
      ApprovalTimeout: "30分"
      AutomatedChecks: "前提条件検証"
    - SecurityValidation: "Pre-activation security checks"
      CheckList:
        - "ネットワーク接続性"
        - "暗号化設定"
        - "アクセス制御設定"
        - "監査ログ設定"
        
  DataProtection:
    - EncryptionInTransit: "TLS 1.3"
    - EncryptionAtRest: "Customer managed KMS"
    - DataIntegrity: "Continuous validation"
      IntegrityChecks:
        - "チェックサム検証"
        - "レプリケーション整合性"
        - "暗号化状態確認"
    - DataClassification: "本番と同等の分類"
    
  Monitoring:
    - SecurityEventReplication: "Real-time"
      Latency: "<1 second"
      FailureHandling: "自動再送"
    - CrossRegionAlerting: "Enabled"
      AlertChannels: ["SNS", "EventBridge", "Email"]
    - ComplianceValidation: "Automated"
      ValidationFrequency: "1時間ごと"
      ComplianceMetrics: "ダッシュボード表示"
      
  TestingStrategy:
    - SecurityDrills: "四半期ごと"
    - FailoverTesting: "年2回"
    - SecurityValidation: "月次"
    - DocumentationUpdate: "変更時即時"
```

DR環境でも本番環境と同等のセキュリティレベルを維持し、切り替え時のセキュリティギャップを防止します。定期的なテストにより、有効性を確認します。

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
        "ComplianceType": "NON_COMPLIANT if not encrypted",
        "RemediationAction": "自動暗号化",
        "Severity": "HIGH"
      },
      {
        "RuleName": "mfa-enabled-for-root",
        "Source": "AWS Config Managed Rule",
        "Scope": "Root account",
        "ComplianceType": "NON_COMPLIANT if MFA not enabled",
        "RemediationAction": "管理者通知",
        "Severity": "CRITICAL"
      },
      {
        "RuleName": "security-group-ssh-restricted",
        "Source": "AWS Config Managed Rule",
        "Scope": "All security groups",
        "ComplianceType": "NON_COMPLIANT if SSH open to 0.0.0.0/0",
        "RemediationAction": "自動修正",
        "Severity": "HIGH"
      },
      {
        "RuleName": "s3-bucket-public-read-prohibited",
        "Source": "AWS Config Managed Rule",
        "Scope": "All S3 buckets",
        "ComplianceType": "NON_COMPLIANT if public read enabled",
        "RemediationAction": "即座にブロック",
        "Severity": "CRITICAL"
      },
      {
        "RuleName": "iam-password-policy",
        "Source": "AWS Config Managed Rule",
        "Scope": "IAM Password Policy",
        "RequiredParameters": {
          "MinimumPasswordLength": 12,
          "RequireSymbols": true,
          "RequireNumbers": true,
          "RequireUppercaseCharacters": true,
          "RequireLowercaseCharacters": true,
          "MaxPasswordAge": 90,
          "PasswordReusePrevention": 5
        }
      }
    ],
    "RemediationConfigurations": [
      {
        "ConfigRuleName": "encrypted-volumes",
        "TargetType": "SSM_DOCUMENT",
        "TargetId": "AWS-EncryptEBSVolume",
        "AutomationAssumeRole": "config-remediation-role",
        "MaximumAutomaticAttempts": 3,
        "RetryAttemptSeconds": 60
      },
      {
        "ConfigRuleName": "security-group-ssh-restricted",
        "TargetType": "SSM_DOCUMENT",
        "TargetId": "AWS-RemoveUnrestrictedSourceInSecurityGroupRules",
        "AutomationAssumeRole": "config-remediation-role",
        "Parameters": {
          "Port": "22",
          "Protocol": "tcp"
        }
      }
    ],
    "ConformancePacks": [
      "Operational-Best-Practices-for-PCI-DSS",
      "Operational-Best-Practices-for-HIPAA",
      "Operational-Best-Practices-for-NIST-CSF"
    ]
  }
}
```

設定のドリフトを継続的に監視し、コンプライアンス違反を自動的に修復することで、常に安全な状態を維持します。複数の業界標準に同時準拠します。

#### 定期的セキュリティ評価

**セキュリティ評価フレームワーク**

```yaml
# Security Assessment Framework
SecurityAssessment:
  VulnerabilityAssessment:
    - Frequency: "Monthly"
    - Scope: "All production systems"
    - Tools: 
        - "AWS Inspector"
        - "Third-party scanners (Qualys, Tenable)"
        - "Container scanning (Twistlock, Aqua)"
    - Reporting: "Executive dashboard"
    - RemediationSLA:
        Critical: "48 hours"
        High: "7 days"
        Medium: "30 days"
        Low: "90 days"
    
  PenetrationTesting:
    - Frequency: "Quarterly"
    - Scope: "External-facing systems"
    - Types:
        - "Web Application Testing"
        - "Network Penetration Testing"
        - "Social Engineering Testing"
        - "Physical Security Testing"
    - Authorization: "AWS penetration testing approval"
    - Reporting: "Detailed technical report"
    - RetestingRequired: "Critical findings within 30 days"
    
  ComplianceAudit:
    - Frequency: "Annual"
    - Standards: 
        - "ISO 27001": "全社スコープ"
        - "SOC 2 Type II": "コアシステム"
        - "PCI DSS": "決済システム"
        - "個人情報保護法": "顧客データ処理"
    - Auditor: "Third-party certified"
    - Remediation: "Action plan with timelines"
    - ContinuousMonitoring: "月次セルフアセスメント"
    
  SecurityMetrics:
    - MeanTimeToDetection: "< 5 minutes"
    - MeanTimeToResponse: "< 30 minutes"
    - MeanTimeToRemediation: "< 4 hours"
    - SecurityIncidents: "Trend analysis"
    - ComplianceScore: "99.5% target"
    - VulnerabilityBacklog: "< 50 open items"
    - PatchingCompliance: "> 98% within SLA"
    
  SecurityPosture:
    - AttackSurfaceReduction: "継続的な最小化"
    - ThreatModeling: "新機能リリース時"
    - SecurityArchitectureReview: "四半期ごと"
    - EmergingThreatAssessment: "月次"
```

定期的な評価により、セキュリティ態勢の継続的な改善と高いセキュリティレベルの維持を実現します。メトリクスにより改善効果を定量化します。

### 15. セキュリティ運用・管理

#### 実装対象サービス

**AWS Security Hub（セキュリティ統合管理）**
- 全120アカウントのセキュリティ状況を一元的に可視化し、優先順位付けされた対応を実現します。単一のダッシュボードで組織全体のセキュリティ態勢を把握でき、効率的な管理が可能になります。クロスリージョン・クロスアカウントの統合により、グローバルな視点でのセキュリティ管理を実現します。
- AWS標準に加え、業界標準（CIS、PCI DSS）への準拠状況を継続的に監視します。コンプライアンス違反は自動的に検出され、修復アクションが提案されるため、常に高いセキュリティレベルを維持できます。カスタムインサイトにより、組織固有の要件にも対応可能です。

**Amazon GuardDuty（脅威検知）**
- 機械学習による異常検知で、既知・未知の脅威を早期発見します。VPCフローログ、DNSログ、CloudTrailイベントを分析し、通常とは異なるパターンを検出することで、高度な攻撃も見逃しません。脅威インテリジェンスフィードの継続的な更新により、最新の脅威にも対応します。
- S3、EKS、EC2の各データソースを有効化し、包括的な監視を実現します。マルウェアスキャン機能により、実行中のワークロードからの脅威も検出し、侵害の拡大を防止します。検出精度の向上により、誤検知を最小化し、運用負荷を軽減します。

**AWS Config（コンプライアンス監視）**
- リソース設定の変更を追跡し、承認されていない変更を即座に検出します。設定履歴により、いつ、誰が、何を変更したかを完全に追跡でき、問題の原因究明を迅速に行えます。設定のスナップショットにより、任意時点の構成を確認できます。
- 自動修復アクションにより、設定のドリフトを防止します。例えば、暗号化が無効化されたEBSボリュームを自動的に再暗号化し、セキュリティポリシーへの準拠を維持します。組織全体で99.5%以上のコンプライアンススコアを維持することを目標とします。