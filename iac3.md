# IaC & CI/CD統合要件

**Infrastructure as Code とCI/CD統合による包括的セキュリティ分析パイプライン**

## プロジェクト背景と統合要件

### 現状の課題と統合の必要性

**従来のモノリシックアーキテクチャからマイクロサービス環境への移行** → TechNova社は現在、従来のモノリシックアーキテクチャから120アカウント構成のマイクロサービス環境への移行を進めています。この大規模な移行により、インフラ管理の複雑化とセキュリティリスクの増大が課題となっています。

**Infrastructure as Code (IaC) とCI/CDパイプライン統合の必要性** → セキュリティ品質を担保しながら開発効率を最大化する包括的なセキュリティ分析システムが必要となりました。手動によるセキュリティチェックでは、120アカウント環境の規模とマイクロサービスの展開速度に対応できないためです。

### 統合セキュリティ分析パイプラインの目的

**多層防御型DevSecOpsパイプラインの実現** → 本要件書は、静的解析、IAM権限分析、動的脆弱性検証を統合した多層防御型のDevSecOpsパイプラインを定義します。これにより、開発プロセスにセキュリティを組み込み、品質と効率の両立を実現します。

**デプロイ前段階での包括的リスク検出** → デプロイ前の段階で潜在的なセキュリティリスクを確実に検出・修正し、120アカウント環境全体のセキュリティガバナンスを実現します。予防的セキュリティアプローチにより、運用後の問題発生を最小化します。

### パイプライン実行順序と処理時間設計

**段階的セキュリティ検証フローの最適化**
```
ソース取得 → 静的解析 → IAM分析 → 動的解析 → 承認 → デプロイ
    ↓          ↓        ↓         ↓       ↓      ↓
  Git取得    構文チェック  権限分析   脆弱性検証  人間判断  実行
    ↓          ↓        ↓         ↓       ↓      ↓
  1-2分     10-20分    5-10分    45-60分   可変   10-20分
```

**処理時間配分の設計根拠** → 各段階の処理時間は、検証の精度と開発者の待機時間のバランスを考慮して設計されています。静的解析は迅速なフィードバックを重視し、動的解析は包括的な検証を実施します。

### 対象サービスと責務分担

**メインパイプライン制御・ワークフロー管理**
- **AWS CodePipeline** → 全体のワークフロー制御を担い、各セキュリティ分析ステージ間の依存関係管理と承認プロセスの統合を実現します。パイプライン実行の可視化と制御により、運用チームの効率的な管理を支援します。

**ステージ別実行環境・分析ツール実行**
- **AWS CodeBuild** → 各セキュリティ分析ツールの実行環境を提供し、Terraform・TFLint・Checkov等の静的解析ツールと動的脆弱性検証ツールを独立したプロジェクトとして管理します。コンテナベースの分離により、ツール間の依存関係の問題を回避します。

**ソースコード管理・バージョン管理**
- **AWS CodeCommit** → Infrastructure as Codeのソースコード管理とバージョン管理を担い、セキュアなGitリポジトリとしてアクセス制御と監査機能を提供します。ブランチ保護とマージ要求によるコードレビュープロセスと統合します。

**アーティファクト保存・ログ管理・レポート保存**
- **AWS S3** → パイプライン実行時のアーティファクト、セキュリティ分析ログ、脆弱性レポートを暗号化して保存し、長期間の監査要件に対応します。ライフサイクルポリシーによる自動アーカイブでコスト最適化を実現します。

**エラー通知・承認要求・アラート配信**
- **AWS SNS** → セキュリティ問題検出時の即座通知、手動承認要求、クリティカルアラートの配信を担います。Slack・Email・SMS等の複数チャネルでの通知により、適切な担当者への迅速なエスカレーションを実現します。

**エラーハンドリング・自動化処理・レポート生成**
- **AWS Lambda** → パイプライン実行時のエラーハンドリング、セキュリティメトリクスの自動集約、日次レポート生成を担います。サーバーレス実行により高い可用性とコスト効率を実現し、障害時の自動対応機能を提供します。

**権限分析・外部アクセス検出**
- **AWS IAM Access Analyzer** → 組織レベルでの権限分析と外部アクセス検出を担い、120アカウント横断での権限関係の可視化と不適切な権限設定の検出を実行します。最小権限の原則の遵守状況を継続的に監視します。

**結果保存・メトリクス追跡・エラー記録**
- **AWS DynamoDB** → セキュリティ分析結果、パフォーマンスメトリクス、エラー履歴を高速に保存し、リアルタイムでの傾向分析と異常検知を可能とします。NoSQLの柔軟性により多様なセキュリティデータ形式に対応します。

**監視・メトリクス・ダッシュボード**
- **Amazon CloudWatch** → パイプライン全体の監視、セキュリティメトリクスの可視化、包括的ダッシュボードの提供を担います。カスタムメトリクスとアラームにより、セキュリティ状況の変化を即座に検知し、プロアクティブな対応を可能とします。

**設定管理・パラメータストア**
- **AWS Systems Manager** → セキュリティツールの設定値、暗号化されたパラメータ、環境固有の構成情報を一元管理します。パラメータストアによるセキュアな設定配布と変更追跡機能を提供します。

**イベント処理・スケジューリング**
- **Amazon EventBridge** → 定期的なセキュリティ分析、日次レポート生成、メトリクス集約のスケジューリングを担います。イベント駆動型のアーキテクチャによる柔軟な処理フローと外部システム統合を実現します。

## セキュリティ分析の3層構造

### 第1層: 静的解析フェーズ（10-20分）

**解析内容と担当ツール**

**Terraform Validate - 構文検証・参照整合性** → Infrastructure as Codeの基本的な構文エラー、リソース参照の整合性、プロバイダー設定の妥当性を検証します。デプロイ前の基本品質を確保し、モジュール間の依存関係チェックにより複雑なインフラ構成でも安定したデプロイメントを保証します。

**TFLint - コード品質・ベストプラクティス** → Terraformコードの品質向上とAWSベストプラクティスの遵守を検証します。パフォーマンス、保守性、セキュリティの観点からコード改善点を特定し、カスタムルールセットにより組織固有の品質標準を自動適用します。

**Checkov - セキュリティ設定・コンプライアンス** → セキュリティ設定の検証とコンプライアンス要件（CIS、NIST、SOC2）への適合性を確認します。500以上の事前定義されたセキュリティルールにより、包括的なセキュリティ検証を自動化し、既知のセキュリティ問題を事前に検出します。

**検証項目の詳細**
- **Infrastructure as Codeの構文エラー・構成ミス** → Terraform HCL文法エラー、リソース定義不備、変数参照エラーの検出により、デプロイ時の障害を予防します。
- **セキュリティベストプラクティスの遵守状況** → 暗号化設定、アクセス制御、ネットワークセキュリティの適切な実装を確認し、セキュリティホールの発生を防止します。
- **コンプライアンス要件（CIS、NIST、SOC2）への適合性** → 業界標準のセキュリティフレームワークへの準拠状況を自動評価し、監査対応を効率化します。
- **リソース設定の一貫性と標準化** → 命名規則、タグ付け標準、リソース設定の組織内統一性を検証し、管理性とガバナンスを向上させます。

### 第2層: IAM分析フェーズ（5-10分）

**解析内容の詳細**

**組織レベル分析 - 120アカウント横断の権限関係** → AWS Organizationsの階層構造を考慮した包括的な権限分析を実行します。アカウント間の信頼関係、権限移譲、リソース共有の適切性を検証し、マルチアカウント環境での権限の可視化により意図しない権限拡大を防止します。

**外部アクセス検出 - 予期しない外部からのアクセス** → 組織外部のAWSアカウントや第三者サービスからの不審なアクセス権限を検出します。Access Analyzerの機械学習機能により、正常なアクセスパターンからの逸脱を自動判定し、データ漏洩リスクを事前に特定します。

**未使用権限特定 - 過剰権限・不要権限の洗い出し** → 90日以上使用されていない権限や実際には不要な過剰権限を特定します。権限使用履歴の分析により最小権限の原則への準拠状況を評価し、セキュリティリスクの削減と管理コストの最適化を同時実現します。

**クロスアカウント信頼関係 - 不適切な信頼関係の検出** → アカウント間のAssumeRole設定やリソースベースポリシーでの不適切な信頼関係を検出します。権限昇格攻撃のリスクを評価し、信頼関係の妥当性検証によりセキュリティ境界の維持を確実にします。

**重点監視項目**
- **外部アカウントからの意図しないアクセス権限** → 組織外からの不審なアクセス許可設定を即座に検出し、データ侵害リスクを最小化します。
- **90日以上使用されていない権限の特定** → 非アクティブな権限を洗い出し、攻撃面を削減することでセキュリティ態勢を強化します。
- **最小権限の原則からの逸脱検出** → 必要以上の権限付与を特定し、権限昇格攻撃のリスクを最小化します。
- **特権アクセスの適切な管理状況** → 管理者権限や機密リソースアクセスの統制状況を確認し、内部脅威対策を強化します。

### 第3層: 動的解析フェーズ（45-60分・並列実行）

**インフラ脆弱性スキャンの実施**
- **ネットワーク・OS・ミドルウェアの脆弱性検証** → ポートスキャン・サービス検出により不要な公開ポートや脆弱なネットワーク設定を特定し、攻撃経路を事前に遮断します。
- **ポートスキャン・サービス検出** → 開放されているポートとサービスの詳細分析により、意図しない公開サービスや脆弱性のあるバージョンを検出します。
- **設定の脆弱性と悪用可能性評価** → セキュリティ設定の実装状況と実際の悪用可能性を評価し、理論的リスクと実際のリスクを区別して優先度を判定します。

**アプリケーション脆弱性スキャンの詳細**
- **OWASP Top 10対応状況の検証** → インジェクション、認証破綻、セッション管理不備、XSS等の主要なWebアプリケーション脆弱性を包括的に検証します。
- **Webアプリケーションの脆弱性スキャン** → 動的解析によるランタイム脆弱性の検出と入力検証の妥当性確認により、実運用時のセキュリティ問題を事前発見します。
- **API エンドポイントのセキュリティ検証** → REST/GraphQL APIの認証・認可・入力検証・レート制限の実装状況を確認し、API経由の攻撃を防止します。

**ペネトレーションテストの実行**
- **実悪用可能性の検証** → 検出された脆弱性の実際の悪用可能性を評価し、攻撃シナリオの実証により真のリスクレベルを判定します。
- **侵入経路の特定** → 複数の脆弱性を組み合わせた攻撃経路の発見と攻撃チェーンの分析により、高度な攻撃手法への対策を講じます。
- **セキュリティ制御の実効性評価** → WAF・IDS/IPS・アクセス制御等のセキュリティ対策の有効性を実証し、防御機能の改善点を特定します。

## パイプライン全体構成

### メインパイプライン設計

**統合セキュリティパイプラインの基本構成**
```hcl
resource "aws_codepipeline" "security_integrated_pipeline" {
  name     = "security-integrated-deployment-pipeline"
  role_arn = aws_iam_role.codepipeline_role.arn

  artifact_store {
    location = aws_s3_bucket.pipeline_artifacts.bucket
    type     = "S3"

    encryption_key {
      id   = aws_kms_key.pipeline_key.arn
      type = "KMS"
    }
  }

  # ソース取得ステージ
  stage {
    name = "Source"

    action {
      name             = "SourceAction"
      category         = "Source"
      owner            = "AWS"
      provider         = "CodeCommit"
      version          = "1"
      output_artifacts = ["source_output"]

      configuration = {
        RepositoryName = aws_codecommit_repository.iac_repo.repository_name
        BranchName     = "main"
      }
    }
  }

  # 静的解析ステージ群
  stage {
    name = "TerraformValidate"

    action {
      name             = "ValidateAction"
      category         = "Build"
      owner            = "AWS"
      provider         = "CodeBuild"
      version          = "1"
      input_artifacts  = ["source_output"]

      configuration = {
        ProjectName = aws_codebuild_project.terraform_validate.name
        EnvironmentVariables = jsonencode([
          {
            name  = "PIPELINE_EXECUTION_ID"
            value = "#{codepipeline.PipelineExecutionId}"
            type  = "PLAINTEXT"
          },
          {
            name  = "ERROR_HANDLING_MODE"
            value = var.error_handling_mode
            type  = "PLAINTEXT"
          }
        ])
      }

      on_failure {
        action_type_id {
          category = "Invoke"
          owner    = "AWS"
          provider = "Lambda"
          version  = "1"
        }

        configuration = {
          FunctionName = aws_lambda_function.pipeline_error_handler.function_name
          UserParameters = jsonencode({
            stage_name    = "TerraformValidate"
            error_type    = "VALIDATION_ERROR"
            pipeline_name = "security-integrated-deployment-pipeline"
          })
        }
      }
    }
  }

  # 手動承認ステージ（Validateエラー時）
  stage {
    name = "ValidateErrorApproval"

    action {
      name     = "ManualApproval"
      category = "Approval"
      owner    = "AWS"
      provider = "Manual"
      version  = "1"

      configuration = {
        NotificationArn = aws_sns_topic.pipeline_approvals.arn
        CustomData      = "Terraform Validate failed. Review errors and approve to continue or reject to stop pipeline."
      }
    }
  }

  # TFLintステージ
  stage {
    name = "TFLint"

    action {
      name             = "LintAction"
      category         = "Build"
      owner            = "AWS"
      provider         = "CodeBuild"
      version          = "1"
      input_artifacts  = ["source_output"]

      configuration = {
        ProjectName = aws_codebuild_project.tflint.name
        EnvironmentVariables = jsonencode([
          {
            name  = "PIPELINE_EXECUTION_ID"
            value = "#{codepipeline.PipelineExecutionId}"
            type  = "PLAINTEXT"
          },
          {
            name  = "ERROR_HANDLING_MODE"
            value = var.error_handling_mode
            type  = "PLAINTEXT"
          }
        ])
      }

      on_failure {
        action_type_id {
          category = "Invoke"
          owner    = "AWS"
          provider = "Lambda"
          version  = "1"
        }

        configuration = {
          FunctionName = aws_lambda_function.pipeline_error_handler.function_name
          UserParameters = jsonencode({
            stage_name    = "TFLint"
            error_type    = "LINTING_ERROR"
            pipeline_name = "security-integrated-deployment-pipeline"
          })
        }
      }
    }
  }

  # Checkovセキュリティ解析ステージ
  stage {
    name = "Checkov"

    action {
      name             = "CheckovAction"
      category         = "Build"
      owner            = "AWS"
      provider         = "CodeBuild"
      version          = "1"
      input_artifacts  = ["source_output"]

      configuration = {
        ProjectName = aws_codebuild_project.checkov.name
        EnvironmentVariables = jsonencode([
          {
            name  = "PIPELINE_EXECUTION_ID"
            value = "#{codepipeline.PipelineExecutionId}"
            type  = "PLAINTEXT"
          },
          {
            name  = "ERROR_HANDLING_MODE"
            value = var.error_handling_mode
            type  = "PLAINTEXT"
          }
        ])
      }

      on_failure {
        action_type_id {
          category = "Invoke"
          owner    = "AWS"
          provider = "Lambda"
          version  = "1"
        }

        configuration = {
          FunctionName = aws_lambda_function.pipeline_error_handler.function_name
          UserParameters = jsonencode({
            stage_name    = "Checkov"
            error_type    = "SECURITY_VIOLATION"
            pipeline_name = "security-integrated-deployment-pipeline"
          })
        }
      }
    }
  }

  # 静的解析完了後の承認ステージ
  stage {
    name = "StaticAnalysisApproval"

    action {
      name     = "StaticAnalysisApproval"
      category = "Approval"
      owner    = "AWS"
      provider = "Manual"
      version  = "1"

      configuration = {
        NotificationArn = aws_sns_topic.security_approvals.arn
        CustomData      = "Static security analysis complete. Review all findings before proceeding to IAM analysis."
      }
    }
  }

  # IAM Access分析ステージ
  stage {
    name = "IAMAccessAnalysis"

    action {
      name             = "AnalyzeIAMAccess"
      category         = "Build"
      owner            = "AWS"
      provider         = "CodeBuild"
      version          = "1"
      input_artifacts  = ["source_output"]

      configuration = {
        ProjectName = aws_codebuild_project.iam_access_analysis.name
        EnvironmentVariables = jsonencode([
          {
            name  = "PIPELINE_EXECUTION_ID"
            value = "#{codepipeline.PipelineExecutionId}"
            type  = "PLAINTEXT"
          },
          {
            name  = "TARGET_ENVIRONMENT"
            value = "staging"
            type  = "PLAINTEXT"
          }
        ])
      }
    }
  }

  # 動的解析結果承認ステージ
  stage {
    name = "DynamicAnalysisApproval"

    action {
      name     = "DynamicAnalysisApproval"
      category = "Approval"
      owner    = "AWS"
      provider = "Manual"
      version  = "1"

      configuration = {
        NotificationArn = aws_sns_topic.security_approvals.arn
        CustomData      = "Dynamic security analysis complete. Review vulnerability scan results and penetration test findings."
      }
    }
  }

  # 開発環境デプロイステージ
  stage {
    name = "DeployDev"

    action {
      name             = "DeployToDev"
      category         = "Build"
      owner            = "AWS"
      provider         = "CodeBuild"
      version          = "1"
      input_artifacts  = ["source_output"]

      configuration = {
        ProjectName = aws_codebuild_project.terraform_deploy_dev.name
        EnvironmentVariables = jsonencode([
          {
            name  = "TARGET_ENVIRONMENT"
            value = "development"
            type  = "PLAINTEXT"
          },
          {
            name  = "TERRAFORM_WORKSPACE"
            value = "dev"
            type  = "PLAINTEXT"
          }
        ])
      }
    }
  }

  # 本番承認ステージ
  stage {
    name = "ProductionApproval"

    action {
      name     = "ProductionDeploymentApproval"
      category = "Approval"
      owner    = "AWS"
      provider = "Manual"
      version  = "1"

      configuration = {
        NotificationArn = aws_sns_topic.production_approvals.arn
        CustomData      = "Development deployment successful. Approve for production deployment."
      }
    }
  }

  # 本番環境デプロイステージ
  stage {
    name = "DeployProd"

    action {
      name             = "DeployToProd"
      category         = "Build"
      owner            = "AWS"
      provider         = "CodeBuild"
      version          = "1"
      input_artifacts  = ["source_output"]

      configuration = {
        ProjectName = aws_codebuild_project.terraform_deploy_prod.name
        EnvironmentVariables = jsonencode([
          {
            name  = "TARGET_ENVIRONMENT"
            value = "production"
            type  = "PLAINTEXT"
          },
          {
            name  = "TERRAFORM_WORKSPACE"
            value = "prod"
            type  = "PLAINTEXT"
          }
        ])
      }
    }
  }

  tags = {
    Purpose     = "Integrated Security Pipeline"
    Environment = "Multi-Account"
    Owner       = "SecurityTeam"
    Project     = "TechNova-DevSecOps"
  }
}
```

**段階的デプロイメントとリスク管理** → Development環境では迅速な検証を重視し、Production環境では厳格な承認プロセスを必須とすることで、開発効率とセキュリティの両立を実現します。Terraform Workspaceによる環境分離により、設定の混在リスクを排除し、安全なマルチ環境運用を確保します。

## IAMロール設計

### CodePipelineサービスロール

**最小権限によるパイプライン実行権限**
```hcl
resource "aws_iam_role" "codepipeline_role" {
  name = "codepipeline-security-pipeline-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "codepipeline.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Purpose     = "CodePipeline Service Role"
    Environment = "Multi-Account"
  }
}

resource "aws_iam_role_policy" "codepipeline_policy" {
  name = "codepipeline-security-pipeline-policy"
  role = aws_iam_role.codepipeline_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetBucketVersioning",
          "s3:PutObject",
          "s3:GetObject",
          "s3:GetObjectVersion"
        ]
        Resource = [
          aws_s3_bucket.pipeline_artifacts.arn,
          "${aws_s3_bucket.pipeline_artifacts.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "codebuild:BatchGetBuilds",
          "codebuild:StartBuild"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction"
        ]
        Resource = [
          aws_lambda_function.pipeline_error_handler.arn
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = [
          aws_sns_topic.pipeline_approvals.arn,
          aws_sns_topic.security_approvals.arn,
          aws_sns_topic.production_approvals.arn
        ]
      }
    ]
  })
}
```

**セキュアな権限管理** → CodePipelineが実行に必要な最小限の権限のみを付与し、S3アクセス・CodeBuild実行・Lambda呼び出し・SNS通知に限定することで、権限昇格攻撃のリスクを最小化します。リソースベースのアクセス制御により不要なリソースへのアクセスを完全に遮断します。

### CodeBuildサービスロール

**包括的セキュリティ分析実行権限**
```hcl
resource "aws_iam_role" "codebuild_role" {
  name = "codebuild-security-analysis-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "codebuild.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Purpose     = "CodeBuild Service Role"
    Environment = "Multi-Account"
  }
}

resource "aws_iam_role_policy" "codebuild_policy" {
  name = "codebuild-security-analysis-policy"
  role = aws_iam_role.codebuild_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion",
          "s3:PutObject"
        ]
        Resource = [
          "${aws_s3_bucket.pipeline_artifacts.arn}/*",
          "${aws_s3_bucket.build_logs.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = [
          aws_sns_topic.pipeline_errors.arn,
          aws_sns_topic.critical_security_alerts.arn
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeVpcs",
          "ec2:DescribeSubnets",
          "ec2:DescribeNetworkAcls"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "cloudwatch:namespace" = [
              "TechNova/SecurityAnalysis",
              "TechNova/IAMSecurity",
              "TechNova/PenetrationTesting"
            ]
          }
        }
      }
    ]
  })
}
```

**条件付きアクセス制御による権限制限** → CloudWatchメトリクス送信を特定のネームスペースに限定し、EC2リソースの読み取り専用権限により、セキュリティ分析に必要な情報収集を安全に実行します。条件付きポリシーにより権限の悪用リスクを最小限に抑制します。

---
## 静的解析の詳細実装

### Terraform Validate プロジェクト

**構文検証とエラーハンドリングの統合**
```hcl
resource "aws_codebuild_project" "terraform_validate" {
  name          = "terraform-validate-with-error-handling"
  description   = "Terraform validation with enhanced error handling"
  service_role  = aws_iam_role.codebuild_role.arn

  artifacts {
    type = "CODEPIPELINE"
  }

  environment {
    compute_type                = "BUILD_GENERAL1_MEDIUM"
    image                      = "aws/codebuild/amazonlinux2-x86_64-standard:latest"
    type                       = "LINUX_CONTAINER"
    image_pull_credentials_type = "CODEBUILD"

    environment_variable {
      name  = "S3_LOG_BUCKET"
      value = aws_s3_bucket.build_logs.id
    }

    environment_variable {
      name  = "ERROR_HANDLER_FUNCTION"
      value = aws_lambda_function.build_error_handler.function_name
    }
  }

  source {
    type      = "CODEPIPELINE"
    buildspec = "buildspecs/validate.yml"
  }

  tags = {
    Stage         = "StaticAnalysis"
    Tool          = "TerraformValidate"
    ErrorHandling = "Enabled"
  }
}
```

**高度なエラー分類とハンドリング** → Terraform実行時のエラーを詳細に分類し、Lambda関数による自動分析・通知・対応提案を実行します。エラーの種類に応じた適切な対応フローの自動選択により、運用効率を大幅に向上させます。

### validate.yml buildspec

**包括的なTerraform検証プロセス**
```yaml
version: 0.2

env:
  variables:
    LOG_FILE: "terraform-validate-$PIPELINE_EXECUTION_ID.log"
    S3_PREFIX: "logs/$PIPELINE_EXECUTION_ID"
    TERRAFORM_VERSION: "1.5.0"

phases:
  install:
    commands:
      - echo "[INSTALL] Setting up environment..." | tee logs/$LOG_FILE
      - mkdir -p logs
      - |
        # Terraform インストール
        wget https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip
        unzip terraform_${TERRAFORM_VERSION}_linux_amd64.zip
        sudo mv terraform /usr/local/bin/
        terraform version | tee -a logs/$LOG_FILE

  pre_build:
    commands:
      - echo "[PRE_BUILD] Initializing Terraform..." | tee -a logs/$LOG_FILE
      - |
        # Backend設定なしでinit（validation用）
        terraform init -backend=false >> logs/$LOG_FILE 2>&1
        INIT_EXIT_CODE=$?
        if [ $INIT_EXIT_CODE -ne 0 ]; then
          echo "[ERROR] Terraform init failed with exit code $INIT_EXIT_CODE" | tee -a logs/$LOG_FILE
          export BUILD_ERROR="TERRAFORM_INIT_FAILED"
          export BUILD_EXIT_CODE=$INIT_EXIT_CODE
        fi

  build:
    commands:
      - echo "[BUILD] Running terraform validate..." | tee -a logs/$LOG_FILE
      - |
        # Terraform validate実行
        terraform validate >> logs/$LOG_FILE 2>&1
        VALIDATE_EXIT_CODE=$?
        
        if [ $VALIDATE_EXIT_CODE -ne 0 ]; then
          echo "[ERROR] Terraform validate failed with exit code $VALIDATE_EXIT_CODE" | tee -a logs/$LOG_FILE
          
          # エラー詳細の解析
          if grep -q "Invalid reference" logs/$LOG_FILE; then
            export SPECIFIC_ERROR="INVALID_REFERENCE"
          elif grep -q "Missing required argument" logs/$LOG_FILE; then
            export SPECIFIC_ERROR="MISSING_ARGUMENT"
          elif grep -q "Duplicate resource" logs/$LOG_FILE; then
            export SPECIFIC_ERROR="DUPLICATE_RESOURCE"
          elif grep -q "Invalid provider configuration" logs/$LOG_FILE; then
            export SPECIFIC_ERROR="INVALID_PROVIDER_CONFIG"
          elif grep -q "Module not found" logs/$LOG_FILE; then
            export SPECIFIC_ERROR="MODULE_NOT_FOUND"
          else
            export SPECIFIC_ERROR="GENERIC_VALIDATION_ERROR"
          fi
          
          export BUILD_ERROR="TERRAFORM_VALIDATE_FAILED"
          export BUILD_EXIT_CODE=$VALIDATE_EXIT_CODE
          
          # エラーハンドリング Lambda を呼び出し
          aws lambda invoke \
            --function-name $ERROR_HANDLER_FUNCTION \
            --payload '{
              "stage": "TerraformValidate",
              "error_type": "'$SPECIFIC_ERROR'",
              "exit_code": '$VALIDATE_EXIT_CODE',
              "pipeline_execution_id": "'$PIPELINE_EXECUTION_ID'",
              "log_file": "'$LOG_FILE'",
              "error_handling_mode": "'$ERROR_HANDLING_MODE'"
            }' \
            /tmp/error_response.json
        else
          echo "[SUCCESS] Terraform validate completed successfully" | tee -a logs/$LOG_FILE
        fi

  post_build:
    commands:
      - echo "[POST_BUILD] Uploading logs and handling errors..." | tee -a logs/$LOG_FILE
      - |
        # ログをS3にアップロード
        aws s3 cp logs/$LOG_FILE s3://$S3_LOG_BUCKET/$S3_PREFIX/$LOG_FILE || echo "S3 upload failed"
        
        # エラーハンドリング
        if [ "$ERROR_HANDLING_MODE" = "STOP" ] && [ ! -z "$BUILD_ERROR" ]; then
          echo "[POST_BUILD] Error handling mode is STOP. Failing build." | tee -a logs/$LOG_FILE
          exit $BUILD_EXIT_CODE
        elif [ "$ERROR_HANDLING_MODE" = "CONTINUE" ] && [ ! -z "$BUILD_ERROR" ]; then
          echo "[POST_BUILD] Error handling mode is CONTINUE. Build continues despite errors." | tee -a logs/$LOG_FILE
          exit 0
        elif [ "$ERROR_HANDLING_MODE" = "MANUAL_APPROVAL" ] && [ ! -z "$BUILD_ERROR" ]; then
          echo "[POST_BUILD] Error handling mode is MANUAL_APPROVAL. Human intervention required." | tee -a logs/$LOG_FILE
          # 手動承認待ちのマーカーファイル作成
          echo "$BUILD_ERROR" > /tmp/manual_approval_required.txt
          aws s3 cp /tmp/manual_approval_required.txt s3://$S3_LOG_BUCKET/$S3_PREFIX/manual_approval_required.txt
          exit 0
        else
          echo "[POST_BUILD] No errors or successful completion" | tee -a logs/$LOG_FILE
          exit 0
        fi

artifacts:
  files:
    - logs/*
    - /tmp/manual_approval_required.txt
  name: terraform-validate-results
```

**インテリジェントなエラー分類** → Terraformのエラーメッセージを詳細に解析し、無効な参照・必須引数の不足・重複リソース・プロバイダー設定エラー・モジュール不存在等の具体的なエラータイプを自動特定します。エラーの種類に応じた修復提案により問題解決を迅速化します。

### TFLint解析プロジェクト

**コード品質とベストプラクティス検証**
```hcl
resource "aws_codebuild_project" "tflint" {
  name          = "tflint-security-analysis"
  description   = "TFLint code quality and best practices analysis"
  service_role  = aws_iam_role.codebuild_role.arn

  artifacts {
    type = "CODEPIPELINE"
  }

  environment {
    compute_type                = "BUILD_GENERAL1_MEDIUM"
    image                      = "aws/codebuild/amazonlinux2-x86_64-standard:latest"
    type                       = "LINUX_CONTAINER"
    image_pull_credentials_type = "CODEBUILD"

    environment_variable {
      name  = "TFLINT_CONFIG_BUCKET"
      value = aws_s3_bucket.security_configs.id
    }

    environment_variable {
      name  = "TFLINT_RULES_SEVERITY"
      value = "HIGH"
    }
  }

  source {
    type      = "CODEPIPELINE"
    buildspec = "buildspecs/tflint.yml"
  }

  tags = {
    Stage    = "StaticAnalysis"
    Tool     = "TFLint"
    Severity = "High"
  }
}
```

**カスタマイズ可能な品質管理** → TFLintの検出結果を重要度別（ERROR・WARNING・NOTICE）に分類し、組織のセキュリティ要件に応じた閾値設定により、適切な品質レベルを自動的に維持します。S3からのカスタム設定読み込みにより、組織固有のルールセットを適用します。

### tflint.yml buildspec（包括的品質分析）

**重要度別品質管理の詳細実装**
```yaml
version: 0.2

env:
  variables:
    LOG_FILE: "tflint-analysis-$PIPELINE_EXECUTION_ID.log"
    S3_PREFIX: "logs/$PIPELINE_EXECUTION_ID"
    TFLINT_VERSION: "0.47.0"
    RESULTS_FILE: "tflint-results.json"

phases:
  install:
    commands:
      - echo "[INSTALL] Setting up TFLint environment..." | tee logs/$LOG_FILE
      - mkdir -p logs
      - |
        # TFLint インストール
        curl -s https://raw.githubusercontent.com/terraform-linters/tflint/master/install_linux.sh | bash
        tflint --version | tee -a logs/$LOG_FILE
        
        # AWS ruleset プラグインのセットアップ
        mkdir -p ~/.tflint.d/plugins
        tflint --init | tee -a logs/$LOG_FILE

  pre_build:
    commands:
      - echo "[PRE_BUILD] Downloading TFLint configuration..." | tee -a logs/$LOG_FILE
      - |
        # カスタム設定をS3からダウンロード
        aws s3 cp s3://$TFLINT_CONFIG_BUCKET/tflint-config/.tflint.hcl .tflint.hcl || echo "Using default config"
        
        # ルールセット設定確認
        if [ -f .tflint.hcl ]; then
          echo "[PRE_BUILD] Using custom TFLint configuration:" | tee -a logs/$LOG_FILE
          cat .tflint.hcl | tee -a logs/$LOG_FILE
        else
          echo "[PRE_BUILD] Creating default TFLint configuration" | tee -a logs/$LOG_FILE
          cat > .tflint.hcl << 'EOF'
plugin "aws" {
  enabled = true
  version = "0.24.1"
  source  = "github.com/terraform-linters/tflint-ruleset-aws"
}

rule "terraform_deprecated_interpolation" {
  enabled = true
}

rule "terraform_unused_declarations" {
  enabled = true
}

rule "terraform_comment_syntax" {
  enabled = true
}

rule "terraform_documented_outputs" {
  enabled = true
}

rule "terraform_documented_variables" {
  enabled = true
}

rule "terraform_typed_variables" {
  enabled = true
}

rule "terraform_module_pinned_source" {
  enabled = true
  style   = "semver"
}

rule "terraform_naming_convention" {
  enabled = true
  format  = "snake_case"
}

rule "terraform_standard_module_structure" {
  enabled = true
}

rule "aws_instance_invalid_type" {
  enabled = true
}

rule "aws_security_group_rule_invalid_protocol" {
  enabled = true
}

rule "aws_db_instance_invalid_type" {
  enabled = true
}

rule "aws_elasticache_cluster_invalid_type" {
  enabled = true
}

rule "aws_alb_invalid_security_group" {
  enabled = true
}

rule "aws_elb_invalid_security_group" {
  enabled = true
}

rule "aws_instance_invalid_ami" {
  enabled = true
}

rule "aws_launch_configuration_invalid_image_id" {
  enabled = true
}

rule "aws_route_invalid_route_table" {
  enabled = true
}
EOF
        fi

  build:
    commands:
      - echo "[BUILD] Running TFLint analysis..." | tee -a logs/$LOG_FILE
      - |
        # TFLint実行（JSON形式で結果出力）
        tflint --format=json --force > logs/$RESULTS_FILE 2>&1
        TFLINT_EXIT_CODE=$?
        
        # 結果をログにも出力（人間が読みやすい形式）
        echo "[BUILD] TFLint Results Summary:" | tee -a logs/$LOG_FILE
        tflint --format=compact | tee -a logs/$LOG_FILE
        
        # JSONから重要度別の問題数を集計
        ERROR_COUNT=$(jq '[.issues[] | select(.rule.severity == "error")] | length' logs/$RESULTS_FILE 2>/dev/null || echo "0")
        WARNING_COUNT=$(jq '[.issues[] | select(.rule.severity == "warning")] | length' logs/$RESULTS_FILE 2>/dev/null || echo "0")
        NOTICE_COUNT=$(jq '[.issues[] | select(.rule.severity == "notice")] | length' logs/$RESULTS_FILE 2>/dev/null || echo "0")
        
        echo "[BUILD] Issues Summary:" | tee -a logs/$LOG_FILE
        echo " - Errors: $ERROR_COUNT" | tee -a logs/$LOG_FILE
        echo " - Warnings: $WARNING_COUNT" | tee -a logs/$LOG_FILE
        echo " - Notices: $NOTICE_COUNT" | tee -a logs/$LOG_FILE
        
        # 重要度に基づく判定
        if [ "$TFLINT_RULES_SEVERITY" = "HIGH" ] && [ "$ERROR_COUNT" -gt 0 ]; then
          echo "[ERROR] High severity mode: Found $ERROR_COUNT error(s)" | tee -a logs/$LOG_FILE
          export BUILD_ERROR="TFLINT_HIGH_SEVERITY_VIOLATIONS"
          export BUILD_EXIT_CODE=1
        elif [ "$TFLINT_RULES_SEVERITY" = "MEDIUM" ] && [ $((ERROR_COUNT + WARNING_COUNT)) -gt 0 ]; then
          echo "[ERROR] Medium severity mode: Found $((ERROR_COUNT + WARNING_COUNT)) error(s)/warning(s)" | tee -a logs/$LOG_FILE
          export BUILD_ERROR="TFLINT_MEDIUM_SEVERITY_VIOLATIONS"
          export BUILD_EXIT_CODE=1
        elif [ "$TFLINT_RULES_SEVERITY" = "LOW" ] && [ $((ERROR_COUNT + WARNING_COUNT + NOTICE_COUNT)) -gt 0 ]; then
          echo "[ERROR] Low severity mode: Found $((ERROR_COUNT + WARNING_COUNT + NOTICE_COUNT)) issue(s)" | tee -a logs/$LOG_FILE
          export BUILD_ERROR="TFLINT_LOW_SEVERITY_VIOLATIONS"
          export BUILD_EXIT_CODE=1
        else
          echo "[SUCCESS] TFLint analysis passed for severity level: $TFLINT_RULES_SEVERITY" | tee -a logs/$LOG_FILE
        fi
        
        # 詳細な違反分析
        if [ ! -z "$BUILD_ERROR" ]; then
          echo "[BUILD] Detailed violation analysis:" | tee -a logs/$LOG_FILE
          jq -r '.issues[] | "Rule: \(.rule.name) | Severity: \(.rule.severity) | File: \(.range.filename):\(.range.start.line) | Message: \(.message)"' logs/$RESULTS_FILE | tee -a logs/$LOG_FILE
        fi

  post_build:
    commands:
      - echo "[POST_BUILD] Processing results and uploading artifacts..." | tee -a logs/$LOG_FILE
      - |
        # CloudWatchメトリクス送信
        aws cloudwatch put-metric-data \
          --namespace "TechNova/SecurityAnalysis" \
          --metric-data \
            MetricName=TFLintErrors,Value=$ERROR_COUNT,Unit=Count \
            MetricName=TFLintWarnings,Value=$WARNING_COUNT,Unit=Count \
            MetricName=TFLintNotices,Value=$NOTICE_COUNT,Unit=Count \
          --region $AWS_DEFAULT_REGION || echo "CloudWatch metrics failed"
        
        # 結果をS3にアップロード
        aws s3 cp logs/$LOG_FILE s3://$S3_LOG_BUCKET/$S3_PREFIX/$LOG_FILE || echo "Log upload failed"
        aws s3 cp logs/$RESULTS_FILE s3://$S3_LOG_BUCKET/$S3_PREFIX/$RESULTS_FILE || echo "Results upload failed"
        
        # エラーハンドリング
        if [ "$ERROR_HANDLING_MODE" = "STOP" ] && [ ! -z "$BUILD_ERROR" ]; then
          echo "[POST_BUILD] Stopping pipeline due to TFLint violations" | tee -a logs/$LOG_FILE
          exit $BUILD_EXIT_CODE
        elif [ "$ERROR_HANDLING_MODE" = "CONTINUE" ] && [ ! -z "$BUILD_ERROR" ]; then
          echo "[POST_BUILD] Continuing pipeline despite TFLint violations" | tee -a logs/$LOG_FILE
          exit 0
        else
          exit 0
        fi

artifacts:
  files:
    - logs/*
  name: tflint-analysis-results
```

**動的品質判定とメトリクス統合** → TFLintの結果を重要度別に分析し、CloudWatchメトリクスとして送信することで、品質トレンドの監視と継続的改善を実現します。詳細な違反分析により、開発者への具体的なフィードバックを提供します。

### Checkov セキュリティ解析プロジェクト

**コンプライアンス対応セキュリティ検証**
```hcl
resource "aws_codebuild_project" "checkov" {
  name          = "checkov-security-compliance"
  description   = "Checkov security and compliance analysis"
  service_role  = aws_iam_role.codebuild_role.arn

  artifacts {
    type = "CODEPIPELINE"
  }

  environment {
    compute_type                = "BUILD_GENERAL1_LARGE"
    image                      = "aws/codebuild/amazonlinux2-x86_64-standard:latest"
    type                       = "LINUX_CONTAINER"
    image_pull_credentials_type = "CODEBUILD"

    environment_variable {
      name  = "CHECKOV_CONFIG_BUCKET"
      value = aws_s3_bucket.security_configs.id
    }

    environment_variable {
      name  = "SECURITY_FRAMEWORK"
      value = "CIS,NIST,SOC2"
    }

    environment_variable {
      name  = "COMPLIANCE_THRESHOLD"
      value = "80"
    }
  }

  source {
    type      = "CODEPIPELINE"
    buildspec = "buildspecs/checkov.yml"
  }

  tags = {
    Stage      = "StaticAnalysis"
    Tool       = "Checkov"
    Compliance = "CIS-NIST-SOC2"
  }
}
```

**マルチフレームワーク コンプライアンス検証** → CIS Benchmarks・NIST Cybersecurity Framework・SOC2要件を同時に検証し、複数のコンプライアンス標準への準拠を自動化します。コンプライアンス閾値の設定により、組織の要求レベルに応じた柔軟な品質管理を実現します。

---
## IAM アクセス分析の詳細実装

### IAM Access Analyzer設定

**組織レベルでの包括的権限分析**
```hcl
# 組織レベルのAccess Analyzer
resource "aws_accessanalyzer_analyzer" "organization_analyzer" {
  analyzer_name = "technova-organization-analyzer"
  type          = "ORGANIZATION"

  tags = {
    Purpose     = "Organization-wide IAM Access Analysis"
    Environment = "Multi-Account"
    Project     = "TechNova-DevSecOps"
  }
}

# アカウントレベルのAccess Analyzer（各アカウント用）
resource "aws_accessanalyzer_analyzer" "account_analyzer" {
  analyzer_name = "technova-account-analyzer"
  type          = "ACCOUNT"

  tags = {
    Purpose     = "Account-level IAM Access Analysis"
    Environment = "Multi-Account"
    Project     = "TechNova-DevSecOps"
  }
}
```

**階層的分析アーキテクチャ** → 組織レベルとアカウントレベルの両方でAccess Analyzerを設定し、マクロ・ミクロ両面からの権限分析を実現します。組織全体の権限トレンドと個別アカウントの詳細分析により、多層的なセキュリティガバナンスを確立します。

### IAM分析CodeBuildプロジェクト

**包括的IAM権限分析の実装**
```hcl
resource "aws_codebuild_project" "iam_access_analysis" {
  name          = "iam-access-comprehensive-analysis"
  description   = "Comprehensive IAM access rights and security analysis"
  service_role  = aws_iam_role.codebuild_iam_analysis_role.arn

  artifacts {
    type = "CODEPIPELINE"
  }

  environment {
    compute_type                = "BUILD_GENERAL1_LARGE"
    image                      = "aws/codebuild/amazonlinux2-x86_64-standard:latest"
    type                       = "LINUX_CONTAINER"
    image_pull_credentials_type = "CODEBUILD"

    environment_variable {
      name  = "ORGANIZATION_ID"
      value = data.aws_organizations_organization.current.id
    }

    environment_variable {
      name  = "ACCOUNT_LIST_BUCKET"
      value = aws_s3_bucket.security_configs.id
    }

    environment_variable {
      name  = "IAM_ANALYSIS_DEPTH"
      value = "COMPREHENSIVE"
    }
  }

  source {
    type      = "CODEPIPELINE"
    buildspec = "buildspecs/iam_analysis.yml"
  }

  tags = {
    Stage = "IAMAnalysis"
    Tool  = "AccessAnalyzer"
    Scope = "Organization"
  }
}
```

**組織規模でのIAM分析** → AWS Organizations配下の全アカウントを対象とした包括的IAM分析により、権限の可視化・異常検知・コンプライアンス評価を自動化します。大規模環境での権限管理の複雑性を解決し、セキュリティリスクの予防的な管理を実現します。

### IAM分析用の拡張ロール

**マルチアカウント分析権限の設計**
```hcl
resource "aws_iam_role" "codebuild_iam_analysis_role" {
  name = "codebuild-iam-analysis-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "codebuild.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Purpose     = "IAM Analysis CodeBuild Role"
    Environment = "Multi-Account"
  }
}

resource "aws_iam_role_policy" "codebuild_iam_analysis_policy" {
  name = "codebuild-iam-analysis-policy"
  role = aws_iam_role.codebuild_iam_analysis_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion",
          "s3:PutObject"
        ]
        Resource = [
          "${aws_s3_bucket.pipeline_artifacts.arn}/*",
          "${aws_s3_bucket.build_logs.arn}/*",
          "${aws_s3_bucket.security_configs.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "access-analyzer:ListAnalyzers",
          "access-analyzer:ListFindings",
          "access-analyzer:GetFinding",
          "access-analyzer:GetAnalyzer",
          "access-analyzer:ListArchiveRules"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "iam:ListRoles",
          "iam:ListUsers",
          "iam:ListGroups",
          "iam:ListPolicies",
          "iam:GetRole",
          "iam:GetUser",
          "iam:GetGroup",
          "iam:GetPolicy",
          "iam:GetPolicyVersion",
          "iam:ListRolePolicies",
          "iam:ListUserPolicies",
          "iam:ListGroupPolicies",
          "iam:ListAttachedRolePolicies",
          "iam:ListAttachedUserPolicies",
          "iam:ListAttachedGroupPolicies",
          "iam:GetRolePolicy",
          "iam:GetUserPolicy",
          "iam:GetGroupPolicy",
          "iam:SimulatePrincipalPolicy",
          "iam:GetAccountSummary"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "organizations:ListAccounts",
          "organizations:DescribeOrganization",
          "organizations:ListRoots",
          "organizations:ListOrganizationalUnitsForParent",
          "organizations:ListAccountsForParent"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "sts:AssumeRole"
        ]
        Resource = "arn:aws:iam::*:role/TechNova-CrossAccount-SecurityAnalysis-Role"
      },
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "cloudwatch:namespace" = "TechNova/IAMSecurity"
          }
        }
      }
    ]
  })
}
```

**クロスアカウント分析権限** → 120アカウント横断でのIAM権限分析に必要な包括的権限を設定し、AssumeRoleによる各アカウントへの安全なアクセスを実現します。Access Analyzer・IAM・Organizationsへの読み取り権限により、組織全体の権限状況を可視化します。

## 動的解析の詳細実装

### 動的脆弱性スキャン（インフラ）

**包括的インフラストラクチャ脆弱性検証**
```hcl
resource "aws_codebuild_project" "dynamic_vuln_scan" {
  name          = "dynamic-infrastructure-vulnerability-scan"
  description   = "Dynamic infrastructure vulnerability scanning using multiple tools"
  service_role  = aws_iam_role.codebuild_role.arn

  artifacts {
    type = "CODEPIPELINE"
  }

  environment {
    compute_type                = "BUILD_GENERAL1_LARGE"
    image                      = "aws/codebuild/amazonlinux2-x86_64-standard:latest"
    type                       = "LINUX_CONTAINER"
    image_pull_credentials_type = "CODEBUILD"
    privileged_mode             = true

    environment_variable {
      name  = "SCAN_TARGET_ENVIRONMENT"
      value = "staging"
    }

    environment_variable {
      name  = "VULNERABILITY_TOOLS"
      value = "nmap,nuclei,testssl"
    }

    environment_variable {
      name  = "SCAN_INTENSITY"
      value = "COMPREHENSIVE"
    }

    environment_variable {
      name  = "MAX_SCAN_DURATION"
      value = "3600" # 1時間
    }
  }

  source {
    type      = "CODEPIPELINE"
    buildspec = "buildspecs/dynamic_vuln_scan.yml"
  }

  timeout_in_minutes = 90

  tags = {
    Stage  = "DynamicAnalysis"
    Tool   = "VulnerabilityScanner"
    Target = "Infrastructure"
  }
}
```

**マルチツール統合による網羅的検証** → Nmap・Nuclei・testssl等の専門ツールを組み合わせ、ネットワーク・OS・ミドルウェアの脆弱性を包括的に検出します。各ツールの特徴を活かした役割分担により、検出精度の向上と偽陽性の削減を実現します。

### 動的アプリケーション脆弱性スキャン

**OWASP準拠の動的セキュリティテスト**
```hcl
resource "aws_codebuild_project" "dynamic_app_scan" {
  name          = "dynamic-application-security-scan"
  description   = "Dynamic application security testing using OWASP ZAP and custom tools"
  service_role  = aws_iam_role.codebuild_role.arn

  artifacts {
    type = "CODEPIPELINE"
  }

  environment {
    compute_type                = "BUILD_GENERAL1_LARGE"
    image                      = "aws/codebuild/amazonlinux2-x86_64-standard:latest"
    type                       = "LINUX_CONTAINER"
    image_pull_credentials_type = "CODEBUILD"
    privileged_mode             = true

    environment_variable {
      name  = "ZAP_SCAN_TYPE"
      value = "FULL"
    }

    environment_variable {
      name  = "OWASP_TOP10_FOCUS"
      value = "true"
    }

    environment_variable {
      name  = "CUSTOM_PAYLOADS_BUCKET"
      value = aws_s3_bucket.security_configs.id
    }
  }

  source {
    type      = "CODEPIPELINE"
    buildspec = "buildspecs/dynamic_app_scan.yml"
  }

  timeout_in_minutes = 120

  tags = {
    Stage  = "DynamicAnalysis"
    Tool   = "OWASP-ZAP"
    Target = "WebApplications"
  }
}
```

**OWASP ZAP統合による業界標準検証** → OWASP ZAPを中核とした動的アプリケーションセキュリティテストにより、SQL Injection・XSS・認証バイパス等のランタイム脆弱性を実際の攻撃シナリオで検証します。カスタムペイロードとの組み合わせにより、組織固有の脅威モデルに対応します。

### ペネトレーションテスト

**自動化ペネトレーションテストの実装**
```hcl
resource "aws_codebuild_project" "penetration_test" {
  name          = "automated-penetration-testing"
  description   = "Automated penetration testing using multiple frameworks"
  service_role  = aws_iam_role.codebuild_role.arn

  artifacts {
    type = "CODEPIPELINE"
  }

  environment {
    compute_type                = "BUILD_GENERAL1_LARGE"
    image                      = "aws/codebuild/amazonlinux2-x86_64-standard:latest"
    type                       = "LINUX_CONTAINER"
    image_pull_credentials_type = "CODEBUILD"
    privileged_mode             = true

    environment_variable {
      name  = "PENTEST_SCOPE"
      value = "EXTERNAL_ONLY"
    }

    environment_variable {
      name  = "PENTEST_INTENSITY"
      value = "MODERATE"
    }

    environment_variable {
      name  = "MAX_PENTEST_DURATION"
      value = "2700" # 45分
    }
  }

  source {
    type      = "CODEPIPELINE"
    buildspec = "buildspecs/penetration_test.yml"
  }

  timeout_in_minutes = 60

  tags = {
    Stage = "DynamicAnalysis"
    Tool  = "PenetrationTest"
    Scope = "Automated"
  }
}
```

**実証的セキュリティ評価** → 複数の攻撃フレームワークを組み合わせ、実際の攻撃シナリオでの悪用可能性を検証します。外部ネットワークからの攻撃を想定したテストにより、実運用環境でのセキュリティ制御の実効性を客観的に評価します。

## エラーハンドリング Lambda 関数

### Lambda関数のコア実装

**インテリジェントな障害対応システム**
```hcl
resource "aws_lambda_function" "pipeline_error_handler" {
  filename         = "lambda/pipeline_error_handler.zip"
  function_name    = "pipeline-error-handler"
  role           = aws_iam_role.lambda_error_handler_role.arn
  handler        = "index.handler"
  source_code_hash = data.archive_file.pipeline_error_handler_zip.output_base64sha256
  runtime        = "python3.9"
  timeout        = 300

  environment {
    variables = {
      SNS_TOPIC_ARN         = aws_sns_topic.pipeline_errors.arn
      DYNAMODB_TABLE        = aws_dynamodb_table.pipeline_errors.name
      S3_BUCKET            = aws_s3_bucket.build_logs.id
      SLACK_WEBHOOK_SECRET = aws_ssm_parameter.slack_webhook.name
    }
  }

  tags = {
    Purpose   = "Pipeline Error Handling"
    Component = "ErrorHandling"
  }
}

data "archive_file" "pipeline_error_handler_zip" {
  type        = "zip"
  output_path = "lambda/pipeline_error_handler.zip"

  source {
    content  = file("${path.module}/lambda/pipeline_error_handler.py")
    filename = "index.py"
  }
}
```

**自動エラー分析と対応** → パイプライン実行時のエラーを自動分析し、エラーの種類・重要度・影響範囲を判定して適切な対応アクションを自動実行します。DynamoDB・SNS・Slackとの統合により、包括的なエラートラッキングと通知を実現します。

### Lambda IAMロール（エラーハンドリング用）

**セキュアなエラーハンドリング権限**
```hcl
resource "aws_iam_role" "lambda_error_handler_role" {
  name = "lambda-pipeline-error-handler-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Purpose   = "Lambda Error Handler Role"
    Component = "ErrorHandling"
  }
}

resource "aws_iam_role_policy" "lambda_error_handler_policy" {
  name = "lambda-pipeline-error-handler-policy"
  role = aws_iam_role.lambda_error_handler_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = [
          aws_sns_topic.pipeline_errors.arn,
          aws_sns_topic.security_escalations.arn
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:GetItem",
          "dynamodb:Query"
        ]
        Resource = aws_dynamodb_table.pipeline_errors.arn
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = [
          "${aws_s3_bucket.build_logs.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "ssm:GetParameter"
        ]
        Resource = [
          aws_ssm_parameter.slack_webhook.arn
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "codepipeline:PutJobSuccessResult",
          "codepipeline:PutJobFailureResult"
        ]
        Resource = "*"
      }
    ]
  })
}
```

**最小権限によるセキュアな運用** → エラーハンドリングLambda関数に必要最小限の権限のみを付与し、エラーデータ保存・通知送信・パイプライン制御に限定することで、セキュリティリスクを最小化します。

### エラー記録用DynamoDBテーブル

**包括的エラートラッキングシステム**
```hcl
resource "aws_dynamodb_table" "pipeline_errors" {
  name           = "pipeline-errors"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "pipeline_execution_id"
  range_key      = "timestamp"

  attribute {
    name = "pipeline_execution_id"
    type = "S"
  }

  attribute {
    name = "timestamp"
    type = "S"
  }

  attribute {
    name = "error_type"
    type = "S"
  }

  attribute {
    name = "severity"
    type = "S"
  }

  global_secondary_index {
    name     = "ErrorTypeIndex"
    hash_key = "error_type"
    range_key = "timestamp"
  }

  global_secondary_index {
    name     = "SeverityIndex"
    hash_key = "severity"
    range_key = "timestamp"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = {
    Purpose   = "Pipeline Error Tracking"
    Component = "ErrorHandling"
  }
}
```

**多次元エラー分析基盤** → エラータイプ・重要度・時系列の多次元インデックスにより、エラー傾向の分析・根本原因の特定・予防策の立案を効率化します。TTL機能による自動データ削除で、長期運用でのコスト最適化を実現します。

## 監視とレポーティングシステム

### CloudWatchダッシュボード

**統合セキュリティ監視ダッシュボード**
```hcl
resource "aws_cloudwatch_dashboard" "security_pipeline_dashboard" {
  dashboard_name = "TechNova-SecurityPipeline-Dashboard"

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
            ["TechNova/SecurityAnalysis", "TFLintErrors"],
            [".", "TFLintWarnings"],
            [".", "CheckovTotalChecks"],
            [".", "CheckovFailedChecks"],
            [".", "CheckovComplianceScore"]
          ]
          view    = "timeSeries"
          stacked = false
          region  = "us-east-1"
          title   = "Static Analysis Metrics"
          period  = 300
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
            ["TechNova/IAMSecurity", "ExternalAccessFindings"],
            [".", "UnusedPermissions"],
            [".", "CrossAccountTrusts"],
            [".", "TotalSecurityFindings"]
          ]
          view    = "timeSeries"
          stacked = false
          region  = "us-east-1"
          title   = "IAM Security Metrics"
          period  = 300
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 8
        height = 6

        properties = {
          metrics = [
            ["TechNova/VulnerabilityScanning", "VulnerabilitiesFound"],
            [".", "HighSeverityVulns"],
            [".", "MediumSeverityVulns"]
          ]
          view    = "timeSeries"
          stacked = true
          region  = "us-east-1"
          title   = "Vulnerability Scan Results"
          period  = 300
        }
      },
      {
        type   = "metric"
        x      = 8
        y      = 6
        width  = 8
        height = 6

        properties = {
          metrics = [
            ["TechNova/ApplicationSecurity", "AppVulnerabilitiesFound"],
            [".", "AppHighSeverityVulns"],
            [".", "InjectionVulnerabilities"]
          ]
          view    = "timeSeries"
          stacked = false
          region  = "us-east-1"
          title   = "Application Security Metrics"
          period  = 300
        }
      },
      {
        type   = "metric"
        x      = 16
        y      = 6
        width  = 8
        height = 6

        properties = {
          metrics = [
            ["TechNova/PenetrationTesting", "VulnerabilitiesExploited"],
            [".", "CriticalPentestFindings"],
            [".", "HighPentestFindings"]
          ]
          view    = "timeSeries"
          stacked = false
          region  = "us-east-1"
          title   = "Penetration Test Results"
          period  = 300
        }
      },
      {
        type   = "log"
        x      = 0
        y      = 12
        width  = 24
        height = 6

        properties = {
          query  = "SOURCE '/aws/codebuild/terraform-validate-with-error-handling' | fields @timestamp, @message | filter @message like /ERROR/ | sort @timestamp desc | limit 50"
          region = "us-east-1"
          title  = "Recent Pipeline Errors"
          view   = "table"
        }
      }
    ]
  })
}
```

**リアルタイムセキュリティ状況の可視化** → 静的解析・IAM分析・脆弱性スキャン・ペネトレーションテストの結果を統合したダッシュボードにより、セキュリティ状況の包括的な監視を実現します。

### セキュリティメトリクス集約Lambda

**自動化された日次レポーティング**
```hcl
resource "aws_lambda_function" "security_metrics_aggregator" {
  filename         = "lambda/security_metrics_aggregator.zip"
  function_name    = "security-metrics-aggregator"
  role            = aws_iam_role.lambda_metrics_role.arn
  handler         = "index.handler"
  source_code_hash = data.archive_file.security_metrics_aggregator_zip.output_base64sha256
  runtime         = "python3.9"
  timeout         = 900

  environment {
    variables = {
      DYNAMODB_TABLE   = aws_dynamodb_table.pipeline_errors.name
      S3_BUCKET        = aws_s3_bucket.build_logs.id
      SNS_TOPIC_ARN    = aws_sns_topic.security_reports.arn
    }
  }

  tags = {
    Purpose   = "Security Metrics Aggregation"
    Component = "Monitoring"
  }
}

# EventBridge rule for daily execution
resource "aws_cloudwatch_event_rule" "daily_security_report" {
  name                = "daily-security-metrics-aggregation"
  description         = "Trigger security metrics aggregation daily"
  schedule_expression = "cron(0 8 * * ? *)" # 毎日午前8時UTC

  tags = {
    Purpose = "Daily Security Reporting"
  }
}

resource "aws_cloudwatch_event_target" "security_metrics_target" {
  rule      = aws_cloudwatch_event_rule.daily_security_report.name
  target_id = "SecurityMetricsAggregatorTarget"
  arn       = aws_lambda_function.security_metrics_aggregator.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.security_metrics_aggregator.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.daily_security_report.arn
}
```

**定期的なセキュリティサマリー生成** → EventBridgeスケジューラーによる定期実行で、日次のセキュリティメトリクス集約・トレンド分析・異常検知を自動化します。

### Lambda IAMロール（メトリクス集約用）

**メトリクス収集専用の権限設計**
```hcl
resource "aws_iam_role" "lambda_metrics_role" {
  name = "lambda-security-metrics-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "lambda_metrics_policy" {
  name = "lambda-security-metrics-policy"
  role = aws_iam_role.lambda_metrics_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:GetMetricStatistics",
          "cloudwatch:ListMetrics"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "dynamodb:Scan",
          "dynamodb:Query"
        ]
        Resource = aws_dynamodb_table.pipeline_errors.arn
      },
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject"
        ]
        Resource = "${aws_s3_bucket.build_logs.arn}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = [
          aws_sns_topic.security_reports.arn,
          aws_sns_topic.security_alerts.arn
        ]
      }
    ]
  })
}
```

**読み取り専用による安全なメトリクス収集** → メトリクス集約に必要な読み取り権限とレポート生成・通知権限のみを付与し、システムへの影響を最小限に抑えます。

## システム全体の依存関係と追加リソース

### S3バケット群

**階層化されたデータ管理**
```hcl
resource "aws_s3_bucket" "pipeline_artifacts" {
  bucket = "technova-pipeline-artifacts-${random_id.bucket_suffix.hex}"

  tags = {
    Purpose     = "CodePipeline Artifacts"
    Environment = "Multi-Account"
  }
}

resource "aws_s3_bucket" "build_logs" {
  bucket = "technova-build-logs-${random_id.bucket_suffix.hex}"

  tags = {
    Purpose     = "Build Logs Storage"
    Environment = "Multi-Account"
  }
}

resource "aws_s3_bucket" "security_configs" {
  bucket = "technova-security-configs-${random_id.bucket_suffix.hex}"

  tags = {
    Purpose     = "Security Configuration Storage"
    Environment = "Multi-Account"
  }
}

resource "random_id" "bucket_suffix" {
  byte_length = 4
}
```

**用途別バケット分離戦略** → パイプラインアーティファクト・ビルドログ・セキュリティ設定を独立したバケットで管理し、データの分離・アクセス制御・ライフサイクル管理を最適化します。

### S3バケット暗号化

**包括的データ保護**
```hcl
resource "aws_s3_bucket_server_side_encryption_configuration" "pipeline_artifacts_encryption" {
  bucket = aws_s3_bucket.pipeline_artifacts.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.pipeline_key.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "build_logs_encryption" {
  bucket = aws_s3_bucket.build_logs.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.pipeline_key.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "security_configs_encryption" {
  bucket = aws_s3_bucket.security_configs.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.pipeline_key.arn
      sse_algorithm     = "aws:kms"
    }
  }
}
```

**統一暗号化による機密性確保** → 全てのS3バケットに対してKMS暗号化を適用し、データの機密性を確保します。

### KMS暗号化キー

**統合暗号化キー管理**
```hcl
resource "aws_kms_key" "pipeline_key" {
  description             = "TechNova Pipeline Encryption Key"
  deletion_window_in_days = 7

  tags = {
    Purpose     = "Pipeline Encryption"
    Environment = "Multi-Account"
  }
}

resource "aws_kms_alias" "pipeline_key_alias" {
  name          = "alias/technova-pipeline-key"
  target_key_id = aws_kms_key.pipeline_key.key_id
}
```

**セキュアなキー管理** → パイプライン全体で使用する統一暗号化キーを管理し、エイリアスによるキー参照の簡素化を実現します。

### SNS通知トピック群

**階層化された通知システム**
```hcl
resource "aws_sns_topic" "pipeline_errors" {
  name = "technova-pipeline-errors"

  tags = {
    Purpose = "Pipeline Error Notifications"
  }
}

resource "aws_sns_topic" "security_reports" {
  name = "technova-security-reports"

  tags = {
    Purpose = "Daily Security Reports"
  }
}

resource "aws_sns_topic" "security_alerts" {
  name = "technova-security-alerts"

  tags = {
    Purpose = "Critical Security Alerts"
  }
}

resource "aws_sns_topic" "critical_security_alerts" {
  name = "technova-critical-security-alerts"

  tags = {
    Purpose = "Critical Security Alerts"
  }
}

resource "aws_sns_topic" "pipeline_approvals" {
  name = "technova-pipeline-approvals"

  tags = {
    Purpose = "Pipeline Manual Approvals"
  }
}

resource "aws_sns_topic" "iam_analysis_approvals" {
  name = "technova-iam-analysis-approvals"

  tags = {
    Purpose = "IAM Analysis Approvals"
  }
}

resource "aws_sns_topic" "production_approvals" {
  name = "technova-production-approvals"

  tags = {
    Purpose = "Production Deployment Approvals"
  }
}
```

**重要度別通知ルーティング** → エラー・レポート・クリティカルアラート・承認要求を独立したSNSトピックで管理し、受信者・通知方法・緊急度に応じた適切なルーティングを実現します。

### SNSトピックポリシー

**セキュアな通知権限管理**
```hcl
resource "aws_sns_topic_policy" "pipeline_errors_policy" {
  arn = aws_sns_topic.pipeline_errors.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = [
            "codebuild.amazonaws.com",
            "codepipeline.amazonaws.com",
            "lambda.amazonaws.com"
          ]
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.pipeline_errors.arn
      }
    ]
  })
}
```

**サービス間通知の安全な許可** → 必要なAWSサービスのみにSNS通知権限を付与し、不要なアクセスを防止します。

### CodeCommitリポジトリ

**セキュアなソースコード管理**
```hcl
resource "aws_codecommit_repository" "iac_repo" {
  repository_name   = "technova-iac-repository"
  repository_description = "TechNova Infrastructure as Code Repository"

  tags = {
    Purpose     = "IaC Source Code"
    Environment = "Multi-Account"
  }
}
```

**Infrastructure as Code専用リポジトリ** → TechNovaのInfrastructure as Codeを一元管理する専用リポジトリとして、セキュアなバージョン管理とアクセス制御を提供します。

### SSMパラメータ（Slack Webhook等）

**機密情報の安全な管理**
```hcl
resource "aws_ssm_parameter" "slack_webhook" {
  name  = "/technova/pipeline/slack-webhook"
  type  = "SecureString"
  value = var.slack_webhook_url

  tags = {
    Purpose   = "Slack Integration"
    Component = "Notifications"
  }
}
```

**暗号化パラメータストア** → Slack WebhookやAPIキー等の機密情報をSSM Parameter Storeで暗号化管理し、Lambda関数やCodeBuildプロジェクトからの安全なアクセスを提供します。

### 変数定義

**設定可能パラメータの定義**
```hcl
variable "slack_webhook_url" {
  description = "Slack Webhook URL for notifications"
  type        = string
  default     = "https://hooks.slack.com/services/CHANGEME"
  sensitive   = true
}

variable "error_handling_mode" {
  description = "Error handling mode: STOP, CONTINUE, or MANUAL_APPROVAL"
  type        = string
  default     = "MANUAL_APPROVAL"

  validation {
    condition     = contains(["STOP", "CONTINUE", "MANUAL_APPROVAL"], var.error_handling_mode)
    error_message = "Error handling mode must be STOP, CONTINUE, or MANUAL_APPROVAL."
  }
}
```

**柔軟な設定管理** → エラーハンドリングモードやSlack通知URLなどの設定可能パラメータにより、組織の要件・リスク許容度・運用方針に応じたカスタマイズを実現します。

### Lambda関数のZIPファイル作成用データソース

**Lambda関数デプロイメント準備**
```hcl
data "archive_file" "security_metrics_aggregator_zip" {
  type        = "zip"
  output_path = "lambda/security_metrics_aggregator.zip"

  source {
    content  = file("${path.module}/lambda/security_metrics_aggregator.py")
    filename = "index.py"
  }
}
```

**自動化されたLambda関数パッケージング** → Terraformによる自動的なZIPファイル作成により、Lambda関数のデプロイメントを簡素化します。

## 出力定義

### 重要なリソース情報の提供

**運用に必要な情報の包括的出力**
```hcl
# 重要なリソースの出力
output "pipeline_name" {
  description = "Name of the security integrated pipeline"
  value       = aws_codepipeline.security_integrated_pipeline.name
}

output "pipeline_arn" {
  description = "ARN of the security integrated pipeline"
  value       = aws_codepipeline.security_integrated_pipeline.arn
}

output "artifacts_bucket" {
  description = "S3 bucket for pipeline artifacts"
  value       = aws_s3_bucket.pipeline_artifacts.bucket
}

output "build_logs_bucket" {
  description = "S3 bucket for build logs and security reports"
  value       = aws_s3_bucket.build_logs.bucket
}

output "security_dashboard_url" {
  description = "CloudWatch Security Dashboard URL"
  value       = "https://console.aws.amazon.com/cloudwatch/home#dashboards:name=${aws_cloudwatch_dashboard.security_pipeline_dashboard.dashboard_name}"
}

output "pipeline_url" {
  description = "CodePipeline Console URL"
  value       = "https://console.aws.amazon.com/codesuite/codepipeline/pipelines/${aws_codepipeline.security_integrated_pipeline.name}/view"
}

output "error_handler_function_name" {
  description = "Error handler Lambda function name"
  value       = aws_lambda_function.pipeline_error_handler.function_name
}

output "metrics_aggregator_function_name" {
  description = "Security metrics aggregator Lambda function name"
  value       = aws_lambda_function.security_metrics_aggregator.function_name
}

output "sns_topics" {
  description = "SNS notification topics"
  value = {
    pipeline_errors           = aws_sns_topic.pipeline_errors.arn
    security_reports         = aws_sns_topic.security_reports.arn
    security_alerts          = aws_sns_topic.security_alerts.arn
    critical_security_alerts = aws_sns_topic.critical_security_alerts.arn
  }
}

output "access_analyzer_arn" {
  description = "Organization Access Analyzer ARN"
  value       = aws_accessanalyzer_analyzer.organization_analyzer.arn
}
```

**運用効率向上のための情報提供** → パイプライン・ダッシュボード・通知システムへの直接アクセスURLと、重要リソースのARN情報を提供することで、運用チームの日常業務効率を大幅に向上させます。

## デプロイメント手順書

### 前提条件

**システム導入の前提要件**

**AWS Organizations設定** → 120アカウント構成のAWS Organizationsと管理アカウントでの実行権限が必要です。組織階層の適切な設定により、マルチアカウント環境でのセキュリティ分析を実現します。

**必要な権限** → 初期構築時にはAdministratorAccessが必要で、以下のサービスへのフルアクセス権限を確保します：
- CodePipeline, CodeBuild, CodeCommit
- IAM, Organizations, Access Analyzer  
- S3, DynamoDB, Lambda, SNS, CloudWatch

**ツールバージョン** → 以下のツールバージョンが必要です：
- Terraform >= 1.5.0
- AWS CLI >= 2.0
- Python >= 3.9

### デプロイメント手順

**段階的導入プロセス**

**ステップ1: 環境変数設定**
```bash
export AWS_REGION=us-east-1
export TECHNOVA_ENVIRONMENT=staging
export SLACK_WEBHOOK_URL="your-slack-webhook-url"
```

**ステップ2: Terraform初期化**
```bash
# Terraform初期化
terraform init
```

**ステップ3: 設定ファイル作成**
```bash
# terraform.tfvars作成
cat > terraform.tfvars << EOF
slack_webhook_url    = "$SLACK_WEBHOOK_URL"
error_handling_mode  = "MANUAL_APPROVAL"
EOF
```

**ステップ4: デプロイメント実行**
```bash
# 計画確認
terraform plan -var-file=terraform.tfvars

# デプロイ実行
terraform apply -var-file=terraform.tfvars
```

**ステップ5: 初期設定**
```bash
# CodeCommitリポジトリのクローン
git clone https://git-codecommit.us-east-1.amazonaws.com/v1/repos/technova-iac-repository
cd technova-iac-repository

# buildspecファイル配置
mkdir -p buildspecs
cp ../buildspecs/* buildspecs/

# 初期コミット
git add .
git commit -m "Initial pipeline configuration"
git push origin main
```

**ステップ6: 通知設定**
```bash
# 通知を受け取りたい場合のみ実行
aws sns subscribe \
  --topic-arn $(terraform output -raw sns_topics | jq -r .security_alerts) \
  --protocol email \
  --notification-endpoint your-email@technova.com
```

**安全なデプロイメント実行** → terraform planによる事前確認とapplyによる段階的実行により、デプロイメントリスクを最小化します。

## 運用開始後の確認項目

### パイプライン動作確認

**システム正常性の検証**
- **CodePipelineの初回実行成功** → 全ステージの正常実行と各セキュリティ分析ツールの動作確認により、システム全体の正常性を検証します。
- **各ステージの正常動作確認** → Terraform Validate・TFLint・Checkov・IAM分析・動的解析の各ステージが想定通りに動作することを確認します。
- **エラーハンドリングの動作確認** → 意図的なエラー発生によるLambda関数の動作とDynamoDBへの記録確認により、障害対応機能を検証します。

### セキュリティ分析確認

**包括的セキュリティ検証の動作確認**
- **静的解析（Terraform Validate, TFLint, Checkov）結果確認** → 各ツールが適切にセキュリティ問題を検出し、レポートを生成することを確認します。
- **IAM Access Analyzer分析結果確認** → 組織レベルでの権限分析が正常に実行され、外部アクセスや未使用権限が適切に検出されることを確認します。
- **動的脆弱性スキャン結果確認** → インフラ・アプリケーション・ペネトレーションテストが並列で実行され、包括的な脆弱性検証が行われることを確認します。
- **ペネトレーションテスト結果確認** → 自動化されたペントestが適切に実行され、実悪用可能性の検証結果が得られることを確認します。

### 監視とアラート確認

**監視システムの正常動作検証**
- **CloudWatchダッシュボード表示確認** → セキュリティメトリクスが正常に可視化され、各分析結果が適切にダッシュボードに反映されることを確認します。
- **SNS通知受信確認** → エラー・アラート・承認要求の各通知が適切な受信者に届くことを確認します。
- **Slack通知受信確認（設定した場合）** → Slack Webhookが正常に動作し、重要な通知がSlackチャネルに投稿されることを確認します。
- **日次セキュリティレポート受信確認** → EventBridgeによる定期実行で日次レポートが生成され、関係者に配信されることを確認します。

### エラーハンドリング確認

**障害対応システムの検証**
- **エラー発生時のLambda関数動作確認** → パイプラインエラー時にLambda関数が正常に起動し、適切なエラー分析・通知が行われることを確認します。
- **DynamoDBへのエラー記録確認** → エラー情報が適切にDynamoDBに記録され、エラータイプ・重要度による分類が正常に動作することを確認します。
- **エスカレーション機能確認** → クリティカルなセキュリティ問題発生時に、適切な関係者への自動エスカレーションが機能することを確認します。

## トラブルシューティング

### よくある問題と解決方法

**運用時の一般的な問題への対処法**

**CodeBuildでのタイムアウト対応**
```bash
# timeout_in_minutesを延長
terraform apply -var="build_timeout=120"
```
**タイムアウト問題の根本解決** → 脆弱性スキャンの並列実行・キャッシュ戦略の最適化・ツール設定の調整により、処理時間を短縮しつつ包括的なセキュリティ検証を維持します。

**IAM権限エラーの診断**
```bash
# 必要な権限をチェック
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::ACCOUNT:role/codebuild-role \
  --action-names iam:ListRoles
```
**権限問題の予防的管理** → IAMポリシーシミュレーターによる事前検証・最小権限の原則の厳格適用・定期的な権限レビューにより、権限関連の問題を予防します。

**S3バケット作成エラー**
```bash
# バケット名の重複を解決
terraform destroy -target=aws_s3_bucket.pipeline_artifacts
terraform apply
```
**バケット名競合の解決** → ランダムサフィックスの使用とグローバル一意性の確保により、バケット名競合を回避します。

## 継続的な保守作業

### 定期保守タスク

**品質維持のための継続的改善**

**週次作業**
- **セキュリティダッシュボードの確認** → CloudWatchダッシュボードでの異常値・トレンド変化の監視と分析により、セキュリティ状況の変化を早期発見します。
- **高優先度のセキュリティ問題対応** → クリティカル・ハイレベルのセキュリティ問題の迅速な修正と検証により、リスクの早期解決を実現します。
- **パイプライン実行成功率の確認** → 実行成功率・エラー率・処理時間のトレンド分析と改善点の特定により、システムの安定性を維持します。

**月次作業**
- **セキュリティポリシーの見直し** → 新しい脅威・コンプライアンス要件に対応したポリシー更新により、セキュリティ水準の継続的向上を図ります。
- **未使用IAM権限のクリーンアップ** → Access Analyzerの分析結果に基づく不要権限の削除と最小権限化により、攻撃面を削減します。
- **脆弱性トレンドの分析** → 検出された脆弱性の傾向分析と予防策の策定により、プロアクティブなセキュリティ対策を実施します。

**四半期作業**
- **セキュリティツールのバージョンアップ** → Terraform・TFLint・Checkov等のツール更新と互換性確認により、最新の脅威に対応します。
- **パイプライン設定の見直し** → 処理時間・リソース使用量・コスト効率の最適化により、運用効率を向上させます。
- **コンプライアンス要件の確認** → 法規制・業界標準の変更に対応したチェック項目の更新により、継続的なコンプライアンス準拠を確保します。

## 緊急時対応手順

### セキュリティインシデント発生時

**迅速な障害対応とリスク最小化**

**パイプライン緊急停止**
```bash
aws codepipeline stop-pipeline-execution \
  --pipeline-name security-integrated-deployment-pipeline \
  --pipeline-execution-id $EXECUTION_ID
```

**影響範囲の調査と評価**
- **CloudWatchログの確認** → エラーログ・実行履歴・メトリクス異常の詳細分析により、問題の根本原因を特定します。
- **セキュリティアラートの分析** → DynamoDBエラーテーブル・SNS通知履歴の確認により、セキュリティ問題の影響範囲を評価します。
- **関連システムへの影響評価** → 120アカウント横断での影響範囲の特定と優先度付けにより、対応リソースを適切に配分します。

**修復対応の実施**
- **脆弱性の修正** → 検出された脆弱性の即座修正とパッチ適用により、セキュリティリスクを排除します。
- **セキュリティ設定の見直し** → 不適切な設定の修正と強化により、類似問題の再発を防止します。
- **パッチの適用** → セキュリティパッチの緊急適用と検証により、脅威を無力化します。

**パイプライン再開**
- **修正内容の検証** → 修正された設定・コード・システムの動作確認により、問題解決を確実にします。
- **テスト環境での動作確認** → ステージング環境での包括的テストにより、本番環境への影響を事前に評価します。
- **本番環境での段階的再開** → 段階的なサービス再開により、リスクを最小化しながら正常運用に復帰します。

### システム障害時

**システム全体の障害対応**

**CloudWatchアラームの確認**
- **メトリクスの異常値確認** → システム全体のパフォーマンスメトリクスを確認し、障害の影響範囲を特定します。
- **ログの詳細分析** → エラーログ・アクセスログの詳細分析により、障害の根本原因を究明します。

**Lambda関数ログの確認**
- **エラーハンドリング関数の動作状況** → エラーハンドリングLambda関数の実行状況とエラー処理結果を確認します。
- **メトリクス集約関数の実行状況** → 日次レポート生成機能の動作状況と集約データの整合性を確認します。

**必要に応じてマニュアル実行**
- **重要なセキュリティチェックの手動実行** → 自動化システム障害時の緊急セキュリティ検証を手動で実施します。
- **緊急時のデプロイ手順実行** → システム復旧のための緊急デプロイメント手順を安全に実行します。

---

**この包括的なセキュリティ分析パイプラインにより、TechNova社の120アカウント環境におけるInfrastructure as Codeのセキュリティ品質を確保し、DevSecOpsプラクティスを実現することができます。**