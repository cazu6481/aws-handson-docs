# セキュリティ要件 Part 2: セクション8-15（データ・運用セキュリティ）

## 8. データベースセキュリティ（Aurora）

### Aurora セキュリティ設定

**データベース暗号化とアクセス制御**

```json
{
  "AuroraSecurityConfiguration": {
    "Encryption": {
      "EncryptionAtRest": {
        "Enabled": true,
        "KMSKey": "service-specific-key",
        "AlgorithmSuite": "AES-256",
        "BackupEncryption": "Same KMS key",
        "SnapshotSharing": "Re-encrypt with target key"
      },
      "EncryptionInTransit": {
        "Enabled": true,
        "TLSVersion": "1.2",
        "CertificateValidation": true,
        "ForceSSL": true,
        "CipherSuites": [
          "TLS_AES_256_GCM_SHA384",
          "TLS_AES_128_GCM_SHA256"
        ]
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
      },
      "DatabaseActivity": {
        "ActivityStream": "Enabled",
        "StreamMode": "Asynchronous",
        "KinesisStream": "aurora-activity-stream"
      }
    },
    "BackupStrategy": {
      "AutomatedBackups": {
        "RetentionPeriod": "35 days",
        "BackupWindow": "03:00-04:00 JST",
        "PreferredMaintenanceWindow": "sun:04:00-sun:05:00"
      },
      "PointInTimeRecovery": true,
      "BacktrackWindow": "72 hours",
      "CrossRegionBackups": {
        "Enabled": true,
        "TargetRegion": "ap-northeast-3",
        "RetentionPeriod": "7 days"
      }
    }
  }
}
```

保存時と転送時の暗号化、IAM認証により、データベースレベルでの多層防御を実現します。データベースアクティビティストリームにより、全ての操作を監査可能にします。

**データベース監査とモニタリング**

```yaml
# Database Security Monitoring
DatabaseAuditing:
  AuditLogging:
    - Events:
        - CONNECTION: "All connection attempts"
        - QUERY: "DML and DDL statements"
        - QUERY_DCL: "Grant/Revoke statements"
        - QUERY_DDL: "Schema changes"
        - QUERY_DML: "Data modifications"
        - TABLE: "Table access"
    - Storage: "CloudWatch Logs"
    - Retention: "90 days"
    - Encryption: "KMS encrypted"
    
  PerformanceInsights:
    - Enabled: true
    - RetentionPeriod: "731 days (2 years)"
    - TopSQL: "Identify expensive queries"
    - WaitEvents: "Database bottleneck analysis"
    - Dimensions: "User, Host, SQL statement"
    
  EnhancedMonitoring:
    - Interval: "1 second"
    - OSMetrics: true
    - ProcessList: true
    - LogAccess: "Real-time via CloudWatch"
    
  Alerting:
    - Categories:
        - SecurityViolations: "Unauthorized access attempts"
        - PerformanceAnomalies: "Unusual query patterns"
        - ConfigurationChanges: "Security setting modifications"
        - FailedAuthentications: "Brute force detection"
    - Channels:
        - SNS: "Security team notifications"
        - Slack: "Real-time alerts"
        - PagerDuty: "Critical incidents"
```

全てのデータベースアクティビティを監視し、不正アクセスや異常を早期検出します。Performance Insightsにより、セキュリティと性能の両面から監視を実現します。

### データ分類と保護

**データ分類フレームワーク**

```json
{
  "DataClassification": {
    "Confidential": {
      "Examples": [
        "customer_personal_data",
        "financial_records",
        "employee_salary",
        "trade_secrets"
      ],
      "EncryptionRequired": true,
      "EncryptionMethod": "Column-level encryption with KMS",
      "AccessRestrictions": "Need-to-know basis",
      "AuditLogging": "Enhanced - all access logged",
      "DataRetention": "Legal requirements (7 years)",
      "DataMasking": "Dynamic data masking for non-prod",
      "BackupRequirements": "Encrypted, geo-redundant"
    },
    "Internal": {
      "Examples": [
        "business_processes",
        "internal_reports",
        "project_data",
        "operational_metrics"
      ],
      "EncryptionRequired": true,
      "EncryptionMethod": "Transparent data encryption",
      "AccessRestrictions": "Employee access only",
      "AuditLogging": "Standard",
      "DataRetention": "7 years",
      "DataMasking": "Static masking for dev/test",
      "BackupRequirements": "Standard encrypted backups"
    },
    "Public": {
      "Examples": [
        "product_specifications",
        "marketing_materials",
        "public_apis",
        "documentation"
      ],
      "EncryptionRequired": false,
      "EncryptionMethod": "Optional TDE",
      "AccessRestrictions": "Public access allowed",
      "AuditLogging": "Basic access logs",
      "DataRetention": "As needed",
      "DataMasking": "Not required",
      "BackupRequirements": "Standard backups"
    }
  }
}
```

データの重要度に応じた保護レベルを適用し、過剰でも不足でもない適切なセキュリティを実現します。列レベル暗号化により、特に機密性の高いデータを追加保護します。

**データマスキングとトークナイゼーション**

```yaml
# Data Protection Strategies
DataProtection:
  DynamicDataMasking:
    - Implementation: "Database-level views"
    - MaskingRules:
        - CreditCard: "Show last 4 digits only"
        - SSN: "XXX-XX-1234 format"
        - Email: "u***@domain.com"
        - Phone: "XXX-XXX-1234"
    - RoleBasedVisibility: "Unmask based on permissions"
    - AuditTrail: "Log all unmask operations"
    
  StaticDataMasking:
    - UseCase: "Non-production environments"
    - Techniques:
        - Shuffling: "Maintain format, scramble data"
        - Substitution: "Replace with fake data"
        - NumberVariance: "±10% for amounts"
        - DateShifting: "Consistent date offsetting"
    - Referential Integrity: "Maintain relationships"
    
  Tokenization:
    - SensitiveData: ["Credit cards", "Bank accounts", "SSN"]
    - TokenVault: "Separate secure database"
    - TokenFormat: "Format-preserving encryption"
    - Access: "Strict vault access control"
    - Performance: "In-memory token cache"
```

動的データマスキングにより、本番データを使用しながらも機密情報を保護します。トークナイゼーションにより、機密データをシステムから分離し、コンプライアンススコープを削減します。

## 9. S3セキュリティ・アクセス制御

### S3バケットセキュリティ設計

**バケット別セキュリティ戦略**

```json
{
  "S3SecurityArchitecture": {
    "バケット分類とセキュリティレベル": {
      "機密データバケット": {
        "Examples": [
          "technova-customer-data-prod",
          "technova-financial-records-prod",
          "technova-employee-data-prod",
          "technova-intellectual-property-prod"
        ],
        "SecurityLevel": "最高",
        "PublicAccessBlock": "全て有効",
        "BucketPolicy": "最小権限の原則",
        "Encryption": "Customer Managed KMS",
        "Versioning": "有効",
        "MFADelete": "必須",
        "AccessLogging": "完全",
        "EventNotifications": "全操作",
        "ObjectLock": {
          "Mode": "GOVERNANCE",
          "RetentionPeriod": "7 years",
          "LegalHold": "Available"
        },
        "ReplicationConfiguration": {
          "Role": "Cross-region replication role",
          "Rules": "All objects to DR region"
        }
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
        "IntelligentTiering": {
          "Enabled": true,
          "ArchiveConfiguration": "90 days to Glacier"
        },
        "CostOptimization": {
          "StorageClassAnalysis": "Enabled",
          "InventoryConfiguration": "Weekly"
        }
      },
      "ログ・監査バケット": {
        "Examples": [
          "technova-cloudtrail-logs-prod",
          "technova-access-logs-prod",
          "technova-security-logs-prod",
          "technova-compliance-logs-prod"
        ],
        "SecurityLevel": "高",
        "PublicAccessBlock": "全て有効",
        "BucketPolicy": "読み取り専用（監査用）",
        "Encryption": "SSE-S3",
        "ObjectLock": {
          "Mode": "COMPLIANCE",
          "RetentionPeriod": "7 years",
          "LegalHold": "Enabled for investigations"
        },
        "ImmutableAccess": "有効",
        "AccessPattern": "Write once, read many",
        "IntegrityValidation": "Digest calculation enabled"
      }
    }
  }
}
```

バケットの用途に応じて適切なセキュリティレベルを適用し、データの重要度に見合った保護を実現します。Object Lockにより、規制要件に準拠した不変性を確保します。

### IAMポリシーとバケットポリシーの組み合わせ

**階層的アクセス制御**

```json
{
  "S3AccessControl": {
    "サービス別IAMポリシー": {
      "manufacturing-service-s3-policy": {
        "Version": "2012-10-17",
        "Statement": [
          {
            "Sid": "AllowServiceSpecificBucketAccess",
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
                "s3:x-amz-acl": "private"
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
                  "workflows/*",
                  "${aws:username}/*"
                ]
              }
            }
          },
          {
            "Sid": "DenyUnencryptedObjectUploads",
            "Effect": "Deny",
            "Action": "s3:PutObject",
            "Resource": "*",
            "Condition": {
              "StringNotEquals": {
                "s3:x-amz-server-side-encryption": ["AES256", "aws:kms"]
              }
            }
          }
        ]
      }
    }
  }
}
```

サービスごとに必要最小限のアクセス権限を付与し、暗号化とHTTPS通信を強制します。条件付きアクセスにより、セキュリティ要件を技術的に強制します。

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

多層的な条件により、暗号化されていない通信やオブジェクトのアップロードを完全に防止します。特定のKMSキーの使用を強制し、データの一貫した保護を確保します。

### S3 Access Points とマルチリージョンアクセス制御

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
              "s3:prefix": ["production/*", "inventory/*"]
              
  sales-customer-data-ap:
    Bucket: "technova-customer-data-prod"
    VPCConfiguration:
      VPCId: "vpc-sales-prod"
    NetworkOrigin: "VPC"
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
            DateBetween:
              "aws:CurrentTime": ["2024-01-01T00:00:00Z", "2025-12-31T23:59:59Z"]
              
  multi-region-access-point:
    Name: "technova-global-data"
    Regions:
      - Region: "ap-northeast-1"
        Bucket: "technova-data-tokyo"
      - Region: "us-east-1"
        Bucket: "technova-data-virginia"
      - Region: "eu-west-1"
        Bucket: "technova-data-ireland"
    PublicAccessBlock:
      BlockPublicAcls: true
      BlockPublicPolicy: true
      IgnorePublicAcls: true
      RestrictPublicBuckets: true
```

Access Pointsにより、同一バケットに対して部門ごとに異なるアクセス制御を適用できます。マルチリージョンアクセスポイントにより、グローバルなデータアクセスを低レイテンシで実現します。

### クロスリージョンレプリケーションセキュリティ

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
          },
          "DeleteMarkerReplication": {
            "Status": "Enabled"
          },
          "ExistingObjectReplication": {
            "Status": "Enabled"
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
            "kms:Decrypt",
            "kms:DescribeKey"
          ],
          "Resource": "arn:aws:kms:ap-northeast-1:123456789012:key/customer-data-key-id",
          "Condition": {
            "StringEquals": {
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
            "StringEquals": {
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

### S3監査・ログ・アラート設定

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
          "ExcludeManagementEventSources": []
        }
      ],
      "InsightSelectors": [
        {
          "InsightType": "ApiCallRateInsight"
        },
        {
          "InsightType": "ApiErrorRateInsight"
        }
      ]
    },
    "S3AccessLogging": {
      "TargetBucket": "technova-s3-access-logs-prod",
      "TargetPrefix": "access-logs/",
      "LogObjectKeyFormat": {
        "SimplePrefix": null,
        "PartitionedPrefix": {
          "PartitionDateSource": "EventTime"
        }
      }
    },
    "EventNotifications": {
      "LambdaConfigurations": [
        {
          "Id": "ObjectCreatedTrigger",
          "LambdaFunctionArn": "arn:aws:lambda:region:account:function:s3-object-scanner",
          "Events": ["s3:ObjectCreated:*"],
          "Filter": {
            "Key": {
              "FilterRules": [
                {
                  "Name": "prefix",
                  "Value": "uploads/"
                }
              ]
            }
          }
        }
      ],
      "TopicConfigurations": [
        {
          "Id": "SecurityAlerts",
          "TopicArn": "arn:aws:sns:region:account:security-alerts",
          "Events": ["s3:ObjectRemoved:*"],
          "Filter": {
            "Key": {
              "FilterRules": [
                {
                  "Name": "prefix",
                  "Value": "sensitive-data/"
                }
              ]
            }
          }
        }
      ],
      "QueueConfigurations": [
        {
          "Id": "ComplianceProcessing",
          "QueueArn": "arn:aws:sqs:region:account:compliance-queue",
          "Events": ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"]
        }
      ]
    }
  }
}
```

全てのS3操作を記録し、機密データへのアクセスや削除を即座に検知します。CloudTrail Insightsにより、異常なAPIコールパターンを自動検出します。

### S3セキュリティ自動化

**自動修復・対応**

```yaml
# S3 Security Automation
S3SecurityAutomation:
  ComplianceMonitoring:
    - PolicyViolationDetection:
        Trigger: "Config Rule違反"
        Response: "自動アラート + 手動修復"
        ConfigRules:
          - s3-bucket-public-read-prohibited
          - s3-bucket-public-write-prohibited
          - s3-bucket-ssl-requests-only
          - s3-bucket-server-side-encryption-enabled
          
    - PublicAccessDetection:
        Trigger: "Public Read/Write検出"
        Response: "即座にブロック + セキュリティチーム通知"
        RemediationAction: 
          Type: "AWS-PublishSNSNotification"
          AutomationAssumeRole: "arn:aws:iam::account:role/remediation"
          
    - UnencryptedObjectDetection:
        Trigger: "暗号化されていないオブジェクト検出"
        Response: "アップロードブロック + 自動暗号化"
        Implementation: "S3 Bucket Policy + Lambda trigger"
        
  AccessAnomalyDetection:
    - UnusualAccessPatterns:
        Detection: "GuardDuty S3 Protection"
        Indicators:
          - "Unusual API calls"
          - "Malicious IP access"
          - "Credential misuse"
        Response: 
          - "IP自動ブロック"
          - "IAM policy attachment"
          - "インシデント作成"
          
    - MassDownloadDetection:
        Detection: "大量ダウンロード (>1GB/hour)"
        Monitoring: "CloudWatch Metrics + Alarms"
        Response: 
          - "一時的アクセス制限"
          - "セッション無効化"
          - "調査開始"
          
    - CrossRegionAccessAnomaly:
        Detection: "通常と異なるリージョンからのアクセス"
        Analysis: "Access pattern baseline comparison"
        Response: 
          - "MFA再認証要求"
          - "ログ強化"
          - "リスクスコア更新"
        
  AutomatedRemediation:
    - S3-Bucket-Public-Access-Prohibited:
        RemediationAction: "AWS-PublishSNSNotification"
        Parameters:
          AutomationAssumeRole: "arn:aws:iam::account:role/remediation"
          TopicArn: "arn:aws:sns:region:account:security-alerts"
          Message: "Public access detected and blocked"
          
    - S3-Default-Encryption-Enabled:
        RemediationAction: "AWS-EnableS3BucketEncryption"
        Parameters:
          AutomationAssumeRole: "arn:aws:iam::account:role/remediation"
          BucketName: "RESOURCE_ID"
          SSEAlgorithm: "AES256"
```

設定違反や異常アクセスを自動的に検出・修復し、人的ミスによるセキュリティインシデントを防止します。GuardDuty S3 Protectionにより、機械学習ベースの脅威検出を実現します。

### GDPR・データ保護法対応のS3設定

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
          "EventBridgeConfiguration": {
            "Enabled": true
          }
        },
        "IntelligentTieringConfiguration": {
          "Id": "PersonalDataTiering",
          "Status": "Enabled",
          "Tierings": [
            {
              "Days": 90,
              "AccessTier": "ARCHIVE_ACCESS"
            },
            {
              "Days": 180,
              "AccessTier": "DEEP_ARCHIVE_ACCESS"
            }
          ]
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
            "Value": "TechNova Corporation"
          }
        ]
      }
    },
    "DataSubjectRightsSupport": {
      "RightToErasure": {
        "Implementation": "Crypto-shredding",
        "Process": {
          "RequestValidation": "Identity verification required",
          "ApprovalWorkflow": "Legal + DPO approval",
          "ExecutionMethod": "Delete encryption keys",
          "VerificationProcess": "Multi-step verification",
          "CompletionNotification": "Automated email"
        },
        "AuditTrail": "Complete deletion record in CloudTrail"
      },
      "RightToAccess": {
        "DataInventory": "S3 Inventory + Athena queries",
        "ResponseTime": "30 days maximum",
        "DeliveryMethod": "Encrypted S3 presigned URL",
        "Format": "JSON, CSV, or PDF",
        "Verification": "Identity validation required"
      },
      "RightToPortability": {
        "ExportFormat": "Structured, machine-readable",
        "Delivery": "Secure transfer to designated controller",
        "Encryption": "End-to-end encryption required"
      }
    }
  }
}
```

GDPR要件に完全準拠し、データ主体の権利行使に迅速に対応できる体制を構築します。Crypto-shreddingにより、暗号鍵の削除でデータを実質的に削除します。

### マイクロサービス別S3アクセスパターン

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
      DataClassification: "Internal"
      EncryptionRequirement: "SSE-S3 minimum"
      
    InventoryManagementService:
      AllowedBuckets:
        - "technova-inventory-data-prod"
        - "technova-manufacturing-shared-prod"
      AllowedActions: ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
      CrossServiceAccess:
        - Service: "SalesOrderService"
          BucketPath: "technova-inventory-data-prod/stock-levels/*"
          Permission: "ReadOnly"
          ValidityPeriod: "1 hour per request"
      EventNotifications:
        - Event: "s3:ObjectCreated:*"
          Target: "inventory-update-queue"
          
  Sales:
    CustomerManagementService:
      AllowedBuckets:
        - "technova-customer-data-prod"
      AllowedActions: ["s3:GetObject", "s3:PutObject"]
      DataClassification: "Confidential"
      EncryptionRequired: "Customer-managed KMS"
      AccessLogging: "Enhanced"
      ComplianceScope: ["GDPR", "PCI DSS"]
      
    OrderProcessingService:
      AllowedBuckets:
        - "technova-order-data-prod"
        - "technova-invoice-data-prod"
      WorkflowIntegration:
        - Step: "Order creation"
          Permission: "Write to orders/"
        - Step: "Invoice generation"
          Permission: "Write to invoices/"
          
  IoT:
    TelemetryService:
      AllowedBuckets:
        - "technova-iot-telemetry-prod"
        - "technova-iot-processed-data-prod"
      AllowedActions: ["s3:PutObject", "s3:GetObject"]
      VolumeRestrictions:
        MaxObjectSize: "100MB"
        DailyUploadLimit: "10GB"
        BurstLimit: "1000 objects/minute"
      LifecycleManagement:
        TransitionToIA: "30 days"
        TransitionToGlacier: "90 days"
        Expiration: "365 days"
      StreamingUpload:
        Enabled: true
        PartSize: "5MB"
        ConcurrentParts: 10
        
    AnalyticsService:
      AllowedBuckets:
        - "technova-iot-analytics-prod"
      DataProcessing:
        InputFormat: "JSON, Parquet"
        OutputFormat: "Parquet with Snappy compression"
        Partitioning: "By date and device type"
      QueryAccess:
        Engine: "Athena"
        Workgroup: "iot-analytics"
        ResultLocation: "s3://technova-query-results/"
```

各マイクロサービスに最適化されたアクセス制御により、最小権限の原則を実現します。サービス固有の要件に応じて、暗号化レベルやアクセスパターンを調整します。

## 10. API セキュリティ（Gateway/Cognito）

### API Gateway セキュリティ設定

**API認証と認可**

```json
{
  "APIGatewaySecurity": {
    "Authentication": {
      "CognitoUserPools": {
        "AuthType": "JWT",
        "TokenValidation": true,
        "ScopeValidation": true,
        "ClaimsValidation": {
          "aud": "Expected audience",
          "iss": "Expected issuer",
          "exp": "Token expiry check"
        },
        "TokenExpiry": "1 hour",
        "RefreshTokenExpiry": "30 days"
      },
      "IAMRoles": {
        "ServiceToService": true,
        "CrossAccountAccess": "Restricted",
        "AssumeRolePolicy": "Explicit trust relationships",
        "SessionDuration": "1 hour maximum"
      },
      "APIKeys": {
        "Usage": "Rate limiting and tracking",
        "Rotation": "Monthly",
        "Storage": "AWS Secrets Manager"
      },
      "OAuth2": {
        "Provider": "Cognito",
        "GrantTypes": ["authorization_code", "client_credentials"],
        "Scopes": ["read", "write", "admin"]
      }
    },
    "Authorization": {
      "ScopeBasedAccess": true,
      "ResourceBasedPolicies": true,
      "ContextualAccess": {
        "Factors": ["IP", "Time", "Device", "Location"],
        "RiskScoring": "ML-based evaluation"
      },
      "FineGrainedControl": {
        "MethodLevel": "GET, POST, PUT, DELETE",
        "ResourceLevel": "/users/{userId}/*",
        "ConditionBased": "Request context evaluation"
      }
    },
    "Throttling": {
      "BurstLimit": 1000,
      "RateLimit": 500,
      "QuotaLimit": "10000/day",
      "PerClientLimits": {
        "Premium": "100000/day",
        "Standard": "10000/day",
        "Free": "1000/day"
      },
      "ThrottlingStrategy": "Token bucket algorithm"
    }
  }
}
```

多層的な認証・認可とレート制限により、APIの悪用を防止します。コンテキストベースのアクセス制御により、リスクに応じた動的な認可を実現します。

**API Gateway WAF統合**

```yaml
# API Gateway WAF Configuration
APIGatewayWAF:
  WebACL:
    Name: "api-gateway-protection"
    Scope: "REGIONAL"
    DefaultAction: "ALLOW"
    
  CustomRules:
    - Name: "API-specific-rate-limit"
      Priority: 1
      Action: "Block"
      Statement:
        RateBasedStatement:
          Limit: 100
          AggregateKeyType: "FORWARDED_IP"
          ScopeDownStatement:
            ByteMatchStatement:
              SearchString: "/api/v1/"
              FieldToMatch:
                UriPath: {}
              TextTransformations:
                - Priority: 0
                  Type: "LOWERCASE"
              PositionalConstraint: "STARTS_WITH"
      VisibilityConfig:
        SampledRequestsEnabled: true
        CloudWatchMetricsEnabled: true
        MetricName: "APIRateLimitRule"
        
    - Name: "API-payload-validation"
      Priority: 2
      Action: "Block"
      Statement:
        AndStatement:
          Statements:
            - SizeConstraintStatement:
                FieldToMatch:
                  Body: {}
                ComparisonOperator: "GT"
                Size: 1048576  # 1MB limit
                TextTransformations:
                  - Priority: 0
                    Type: "NONE"
            - NotStatement:
                Statement:
                  ByteMatchStatement:
                    SearchString: "application/json"
                    FieldToMatch:
                      SingleHeader:
                        Name: "content-type"
                    TextTransformations:
                      - Priority: 0
                        Type: "LOWERCASE"
                    PositionalConstraint: "CONTAINS"
                    
    - Name: "SQL-injection-protection"
      Priority: 3
      Action: "Block"
      Statement:
        OrStatement:
          Statements:
            - SqliMatchStatement:
                FieldToMatch:
                  Body: {}
                TextTransformations:
                  - Priority: 0
                    Type: "URL_DECODE"
                  - Priority: 1
                    Type: "HTML_ENTITY_DECODE"
            - SqliMatchStatement:
                FieldToMatch:
                  AllQueryArguments: {}
                TextTransformations:
                  - Priority: 0
                    Type: "URL_DECODE"
```

API固有の脅威に対する防御を実装し、ペイロードサイズやコンテンツタイプの検証を行います。SQLインジェクション対策により、データベースへの攻撃を防止します。

**API バージョニングとセキュリティ**

```json
{
  "APIVersioning": {
    "Strategy": "URI path versioning",
    "VersionFormat": "/api/v{version}/",
    "SupportedVersions": ["v1", "v2", "v3"],
    "DeprecationPolicy": {
      "NoticePerior": "6 months",
      "SunsetPeriod": "12 months",
      "MigrationSupport": "Provided"
    },
    "SecurityByVersion": {
      "v1": {
        "Status": "Deprecated",
        "Security": "Basic auth only",
        "RateLimit": "100/hour",
        "EndOfLife": "2024-12-31"
      },
      "v2": {
        "Status": "Current",
        "Security": "OAuth 2.0",
        "RateLimit": "1000/hour",
        "Features": ["JWT validation", "Scope-based access"]
      },
      "v3": {
        "Status": "Beta",
        "Security": "mTLS + OAuth 2.0",
        "RateLimit": "5000/hour",
        "Features": ["Zero-trust", "Contextual auth"]
      }
    }
  }
}
```

APIバージョニングにより、後方互換性を保ちながらセキュリティを段階的に強化します。古いバージョンには制限を設け、新バージョンへの移行を促進します。

### Cognito セキュリティ強化

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
      "PasswordHistory": {
        "Count": 24,
        "PreventReuse": true
      },
      "CommonPasswordCheck": true,
      "BreachedPasswordCheck": true
    },
    "MFAConfiguration": {
      "MFARequired": true,
      "AllowedMFATypes": ["SMS", "TOTP", "WebAuthn"],
      "PreferredMFA": "TOTP",
      "BackupCodes": {
        "Enabled": true,
        "Count": 10,
        "OneTimeUse": true
      },
      "RiskBasedMFA": {
        "Enabled": true,
        "RiskThreshold": "Medium"
      }
    },
    "AccountSecurity": {
      "AccountRecovery": {
        "Methods": ["Email", "Phone", "SecurityQuestions"],
        "RequiredMethods": 2,
        "RecoveryCodeExpiry": "24 hours"
      },
      "PreventUserExistenceErrors": true,
      "AdvancedSecurityMode": "ENFORCED",
      "CompromisedCredentials": {
        "EventAction": "BLOCK",
        "NotifyUser": true
      }
    },
    "DeviceTracking": {
      "ChallengeRequiredOnNewDevice": true,
      "DeviceOnlyRememberedOnUserPrompt": true,
      "MaxDevicesPerUser": 5,
      "DeviceFingerprintingMethod": "Advanced"
    },
    "AdaptiveAuthentication": {
      "Enabled": true,
      "RiskConfiguration": {
        "LowRisk": "Allow",
        "MediumRisk": "MFA required",
        "HighRisk": "Block + Admin notification"
      }
    }
  }
}
```

強固なパスワードポリシーとMFA必須化により、アカウント乗っ取りのリスクを最小化します。適応型認証により、リスクレベルに応じた動的なセキュリティ制御を実現します。

**Cognito Identity Pool セキュリティ**

```yaml
# Cognito Identity Pool Configuration
IdentityPoolSecurity:
  AuthenticationProviders:
    - CognitoUserPool:
        UserPoolId: "ap-northeast-1_xxxxx"
        ClientId: "xxxxxxxxxxxxx"
        ServerSideTokenCheck: true
    - SAML:
        ProviderName: "CompanySAML"
        IdentityProviderUrl: "https://idp.technova.com"
    - OIDC:
        ProviderName: "GoogleAuth"
        ClientId: "google-client-id"
        
  RoleMapping:
    Type: "Token"
    AmbiguousRoleResolution: "Deny"
    RulesConfiguration:
      Rules:
        - Claim: "custom:department"
          MatchType: "Equals"
          Value: "Engineering"
          RoleARN: "arn:aws:iam::account:role/EngineeringRole"
        - Claim: "custom:level"
          MatchType: "GreaterThan"
          Value: "5"
          RoleARN: "arn:aws:iam::account:role/SeniorRole"
          
  SecurityConfiguration:
    AllowUnauthenticatedIdentities: false
    DeveloperProviderName: null
    IdentityPoolTags:
      - Environment: "Production"
      - SecurityLevel: "High"
```

フェデレーテッドアイデンティティの統合により、複数の認証プロバイダーをサポートしながら、一貫したアクセス制御を実現します。

## 11. Secrets Management と Key Management

### AWS Secrets Manager統合

**シークレット管理戦略**

```json
{
  "SecretsManagement": {
    "SecretCategories": {
      "DatabaseCredentials": {
        "Scope": "Per-microservice",
        "RotationEnabled": true,
        "RotationInterval": "30 days",
        "RotationFunction": "arn:aws:lambda:region:account:function:rotate-db-credentials",
        "EncryptionKey": "service-specific-kms-key",
        "VersioningStrategy": "Automatic with staging labels",
        "AccessPattern": "Application integration via SDK"
      },
      "APIKeys": {
        "Scope": "Per-integration",
        "RotationEnabled": true,
        "RotationInterval": "90 days",
        "NotificationChannels": ["Email", "SNS"],
        "AccessLogging": "Enhanced",
        "UsageTracking": "CloudWatch metrics",
        "RateLimiting": "Per-key quotas"
      },
      "CertificateKeys": {
        "Scope": "Per-domain",
        "RotationEnabled": true,
        "RotationInterval": "365 days",
        "CertificateAuthority": "AWS ACM",
        "BackupStrategy": "Multi-region replication",
        "ComplianceTracking": "Certificate expiry monitoring"
      },
      "EncryptionKeys": {
        "Scope": "Per-data-classification",
        "KeyType": "Symmetric/Asymmetric",
        "Algorithm": "AES-256/RSA-2048",
        "Usage": "Data encryption keys",
        "Derivation": "From master keys"
      }
    },
    "AccessControl": {
      "ResourceBasedPolicies": {
        "PrincipalRestrictions": "Specific IAM roles only",
        "ConditionKeys": ["aws:SourceIp", "aws:RequestedRegion"],
        "CrossAccountAccess": "Explicit trust only"
      },
      "IAMRoleBasedAccess": {
        "LeastPrivilege": "Secret-specific permissions",
        "TemporaryAccess": "STS tokens with expiry",
        "AuditTrail": "CloudTrail integration"
      },
      "VPCEndpointAccess": {
        "PrivateConnectivity": "No internet routing",
        "EndpointPolicies": "Restrictive access",
        "DNSResolution": "Private hosted zones"
      }
    },
    "SecretVersioning": {
      "Strategy": "Staging labels",
      "Labels": ["AWSCURRENT", "AWSPENDING", "AWSPREVIOUS"],
      "RollbackCapability": "Instant version switch",
      "HistoryRetention": "Configurable per secret"
    }
  }
}
```

自動ローテーションにより、長期間同じ認証情報を使用するリスクを排除し、侵害時の影響を限定します。バージョニングにより、問題発生時の迅速なロールバックを可能にします。

**シークレットローテーション自動化**

```yaml
# Secret Rotation Configuration
SecretRotation:
  DatabasePasswordRotation:
    RotationLambda: "arn:aws:lambda:region:account:function:SecretsManagerRDSMySQLRotation"
    RotationRules:
      AutomaticallyAfterDays: 30
      Duration: "2 hours"
      ScheduleExpression: "rate(30 days)"
    RotationStrategy:
      Type: "Single user rotation"
      Steps:
        - CreateSecret: "Generate new password"
        - SetSecret: "Update database password"
        - TestSecret: "Verify connectivity"
        - FinishSecret: "Update version labels"
    ErrorHandling:
      MaxRetries: 3
      BackoffStrategy: "Exponential"
      AlertOnFailure: true
      
  APIKeyRotation:
    CustomRotationFunction: true
    ImplementationSteps:
      - GenerateNewKey: "Create in external system"
      - UpdateApplications: "Gradual rollout"
      - ValidateUsage: "Monitor for errors"
      - DeprecateOldKey: "After validation period"
      - RemoveOldKey: "Final cleanup"
    ValidationPeriod: "24 hours"
    RollbackOnError: true
```

段階的なローテーションプロセスにより、サービス中断なく認証情報を更新します。検証期間を設けることで、問題を早期に発見し対処できます。

### KMS Key Management

**暗号化キー階層**

```yaml
# KMS Key Management Strategy
KMSKeyHierarchy:
  MasterKeys:
    OrganizationRootKey:
      Type: "AWS Managed CMK"
      Purpose: "Root of trust"
      Usage: "Key derivation only"
      AccessControl: "Executive approval required"
      
  CustomerMasterKeys:
    - Purpose: "Service Encryption"
      Type: "Customer Managed CMK"
      Usage: "Per-microservice"
      KeySpec: "SYMMETRIC_DEFAULT"
      KeyRotation: "Annual"
      MultiRegion: true
      KeyPolicy:
        Administrators: ["SecurityAdminRole"]
        Users: ["ServiceRole", "ApplicationRole"]
        
    - Purpose: "Data Encryption"
      Type: "Customer Managed CMK"
      Usage: "Per-data-classification"
      KeySpec: "SYMMETRIC_DEFAULT"
      KeyRotation: "Annual"
      Tags:
        - DataClassification: "Confidential"
        - Compliance: "GDPR"
        
    - Purpose: "Signing"
      Type: "Customer Managed CMK"
      Usage: "Code and document signing"
      KeySpec: "RSA_2048"
      KeyUsage: "SIGN_VERIFY"
      
  DataEncryptionKeys:
    Generation: "On-demand from CMK"
    Caching: "5 minutes in memory"
    Scope: "Per-encryption operation"
    Cleanup: "Secure memory wipe"
    
  KeyPolicies:
    - Principal: "Service Roles"
      Actions: 
        - "kms:Decrypt"
        - "kms:GenerateDataKey"
      Conditions:
        - StringEquals:
            "kms:ViaService": "s3.region.amazonaws.com"
        - StringLike:
            "kms:EncryptionContext:aws:s3:arn": "arn:aws:s3:::bucket-name/*"
```

階層的なキー管理により、適切なアクセス制御と監査性を実現し、キーの不正使用を防止します。マルチリージョンキーにより、災害時の可用性を確保します。

**暗号化コンテキストとキーポリシー**

```json
{
  "EncryptionContextUsage": {
    "Purpose": "Additional authentication for key usage",
    "Implementation": {
      "S3Objects": {
        "bucket": "bucket-name",
        "key": "object-key",
        "version": "object-version-id"
      },
      "DatabaseRecords": {
        "database": "database-name",
        "table": "table-name",
        "primary-key": "record-id"
      },
      "ApplicationSecrets": {
        "application": "app-name",
        "environment": "production",
        "secret-name": "secret-id"
      }
    },
    "Validation": "Automatic by KMS",
    "AuditLogging": "CloudTrail records all contexts"
  },
  "KeyPolicyExamples": {
    "ServiceSpecificAccess": {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "Enable IAM User Permissions",
          "Effect": "Allow",
          "Principal": {
            "AWS": "arn:aws:iam::account:root"
          },
          "Action": "kms:*",
          "Resource": "*"
        },
        {
          "Sid": "Allow use of the key for specific service",
          "Effect": "Allow",
          "Principal": {
            "AWS": "arn:aws:iam::account:role/ServiceRole"
          },
          "Action": [
            "kms:Decrypt",
            "kms:GenerateDataKey"
          ],
          "Resource": "*",
          "Condition": {
            "StringEquals": {
              "kms:ViaService": [
                "s3.ap-northeast-1.amazonaws.com",
                "secretsmanager.ap-northeast-1.amazonaws.com"
              ]
            }
          }
        }
      ]
    }
  }
}
```

暗号化コンテキストにより、キーの使用を特定のリソースやサービスに限定し、キーの誤用を防止します。

## 12. 監視・ログ・インシデント対応

### 統合セキュリティ監視

**Security Hub統合**

```json
{
  "SecurityHubConfiguration": {
    "EnabledStandards": [
      {
        "StandardsArn": "arn:aws:securityhub:::standards/aws-foundational-security-best-practices/v/1.0.0",
        "Enabled": true,
        "DisabledControls": []
      },
      {
        "StandardsArn": "arn:aws:securityhub:::standards/cis-aws-foundations-benchmark/v/1.2.0",
        "Enabled": true,
        "DisabledControls": ["CIS.2.8"]
      },
      {
        "StandardsArn": "arn:aws:securityhub:::standards/pci-dss/v/3.2.1",
        "Enabled": true,
        "DisabledControls": []
      }
    ],
    "CustomInsights": [
      {
        "Name": "High-Severity-Findings",
        "Filters": {
          "SeverityLabel": ["HIGH", "CRITICAL"],
          "WorkflowStatus": ["NEW", "NOTIFIED"],
          "RecordState": ["ACTIVE"],
          "ComplianceStatus": ["FAILED"]
        },
        "GroupByAttribute": "ResourceType"
      },
      {
        "Name": "Compliance-Failures",
        "Filters": {
          "ComplianceStatus": ["FAILED"],
          "RecordState": ["ACTIVE"],
          "ProductArn": ["arn:aws:securityhub:*:*:product/aws/config"]
        },
        "GroupByAttribute": "ComplianceSecurityControlId"
      },
      {
        "Name": "Unresolved-Critical-Findings",
        "Filters": {
          "SeverityLabel": ["CRITICAL"],
          "WorkflowStatus": ["NEW", "NOTIFIED"],
          "UpdatedAt": [{"DateRange": {"Value": 7, "Unit": "DAYS"}}]
        },
        "GroupByAttribute": "ProductName"
      }
    ],
    "Automation": {
      "AutomatedRemediationEnabled": true,
      "RemediationActions": {
        "S3BucketPublicAccessBlock": {
          "FindingType": "S3.Bucket.PublicAccess",
          "Action": "EnablePublicAccessBlock",
          "AutoApprove": true
        },
        "IAMPasswordPolicy": {
          "FindingType": "IAM.PasswordPolicy",
          "Action": "UpdatePasswordPolicy",
          "AutoApprove": false
        }
      },
      "NotificationTargets": [
        {
          "Type": "SNS",
          "Target": "arn:aws:sns:region:account:security-team-critical",
          "Severity": ["CRITICAL"]
        },
        {
          "Type": "Email",
          "Target": "security-team@technova.com",
          "Severity": ["HIGH", "CRITICAL"]
        }
      ],
      "EscalationProcedures": {
        "L1": "Security analyst review",
        "L2": "Senior security engineer",
        "L3": "CISO notification"
      }
    },
    "IntegrationSettings": {
      "TicketingSystem": "ServiceNow",
      "SIEMIntegration": "Splunk",
      "ChatOps": "Slack",
      "CustomWebhook": "https://api.technova.com/security-events"
    }
  }
}
```

Security Hubにより、複数のセキュリティサービスからの検出事項を一元管理し、優先順位付けされた対応を実現します。カスタムインサイトにより、組織固有の脅威に焦点を当てた監視が可能です。

**CloudTrail統合監査**

```yaml
# CloudTrail Security Configuration
CloudTrailSecurity:
  OrganizationTrail:
    - Name: "technova-org-trail"
      IsMultiRegionTrail: true
      IncludeGlobalServiceEvents: true
      IsOrganizationTrail: true
      EnableLogFileValidation: true
      
  EventSelectors:
    - ReadWriteType: "All"
      IncludeManagementEvents: true
      DataResources:
        - Type: "AWS::S3::Object"
          Values: ["arn:aws:s3:::*/"]
        - Type: "AWS::Lambda::Function"
          Values: ["arn:aws:lambda:*:*:function/*"]
        - Type: "AWS::DynamoDB::Table"
          Values: ["arn:aws:dynamodb:*:*:table/*"]
          
  AdvancedEventSelectors:
    - Name: "LogAllS3ObjectAccess"
      FieldSelectors:
        - Field: "eventCategory"
          Equals: ["Data"]
        - Field: "resources.type"
          Equals: ["AWS::S3::Object"]
          
  InsightSelectors:
    - InsightType: "ApiCallRateInsight"
    - InsightType: "ApiErrorRateInsight"
    
  LogDelivery:
    S3BucketName: "technova-cloudtrail-logs"
    S3KeyPrefix: "AWSLogs/"
    SnsTopicName: "cloudtrail-log-notification"
    CloudWatchLogsLogGroupArn: "arn:aws:logs:region:account:log-group:cloudtrail"
    
  LogAnalysis:
    - RealTimeProcessing: 
        Method: "Kinesis Data Streams"
        Analytics: "Kinesis Analytics"
    - AnomalyDetection:
        Service: "CloudWatch Anomaly Detector"
        Baseline: "30 days"
    - ThreatIntelligence:
        Integration: "GuardDuty"
        CustomRules: "Lambda processors"
```

全てのAPIコールを記録し、異常なアクティビティパターンを機械学習により早期検出します。CloudTrail Insightsにより、通常とは異なるAPI使用パターンを自動検出します。

**GuardDuty脅威検知強化**

```json
{
  "GuardDutyEnhancement": {
    "ThreatIntelligence": {
      "CustomThreatLists": [
        {
          "Name": "IndustrySpecificThreats",
          "Location": "s3://threat-intel/manufacturing-threats.txt",
          "Format": "TXT",
          "UpdateFrequency": "Daily"
        },
        {
          "Name": "PartnerSharedIntel",
          "Location": "s3://threat-intel/partner-iocs.txt",
          "Format": "STIX",
          "UpdateFrequency": "Hourly"
        }
      ],
      "TrustedIPLists": [
        {
          "Name": "CorporateOffices",
          "Location": "s3://threat-intel/office-ips.txt",
          "AutoUpdate": true
        },
        {
          "Name": "BusinessPartners",
          "Location": "s3://threat-intel/partner-ips.txt",
          "ReviewRequired": true
        }
      ]
    },
    "FindingProcessing": {
      "AutomatedResponse": {
        "HighSeverity": {
          "Actions": [
            "Isolate instance",
            "Revoke credentials",
            "Notify security team"
          ],
          "RequireApproval": false
        },
        "MediumSeverity": {
          "Actions": [
            "Tag resource",
            "Create ticket",
            "Enhanced monitoring"
          ],
          "RequireApproval": true
        }
      },
      "Integration": {
        "SIEM": "Real-time streaming via Kinesis",
        "Ticketing": "Auto-create in ServiceNow",
        "Notification": "Multi-channel alerts"
      }
    },
    "CoverageOptimization": {
      "S3Protection": {
        "Enabled": true,
        "MonitoredBuckets": "All production buckets"
      },
      "EKSProtection": {
        "Enabled": true,
        "AuditLogs": true,
        "RuntimeMonitoring": true
      },
      "LambdaProtection": {
        "Enabled": true,
        "NetworkLogs": true
      }
    }
  }
}
```

カスタム脅威インテリジェンスの統合により、業界固有の脅威に対する検知能力を向上させます。自動化された対応により、脅威への初動を高速化します。

### インシデント対応フレームワーク

**自動インシデント対応**

```json
{
  "IncidentResponse": {
    "DetectionSources": [
      {
        "Source": "GuardDuty",
        "Priority": "High",
        "AutoResponse": true
      },
      {
        "Source": "Security Hub",
        "Priority": "Critical findings only",
        "AutoResponse": true
      },
      {
        "Source": "CloudWatch Alarms",
        "Priority": "Based on alarm severity",
        "AutoResponse": false
      },
      {
        "Source": "VPC Flow Logs",
        "Priority": "Anomaly detection",
        "AutoResponse": false
      },
      {
        "Source": "WAF Logs",
        "Priority": "Rate limit exceeded",
        "AutoResponse": true
      },
      {
        "Source": "Custom Applications",
        "Priority": "Application-defined",
        "AutoResponse": false
      }
    ],
    "ResponseAutomation": {
      "IsolationProcedures": {
        "NetworkIsolation": {
          "Method": "Security group modification",
          "Implementation": "Remove all ingress rules",
          "PreservationRules": "Maintain forensic access"
        },
        "AccessRevocation": {
          "IAMUsers": "Disable access keys",
          "IAMRoles": "Attach deny-all policy",
          "Sessions": "Revoke all active sessions"
        },
        "TrafficBlocking": {
          "WAF": "Add IP to block list",
          "NACLs": "Deny specific IPs",
          "RouteTable": "Black hole routing"
        }
      },
      "NotificationProcedures": {
        "SecurityTeam": {
          "Method": "PagerDuty",
          "Escalation": "5-minute intervals",
          "Channels": ["SMS", "Phone", "Email"]
        },
        "Management": {
          "Criteria": "Critical incidents only",
          "Format": "Executive summary",
          "Timing": "Within 1 hour"
        },
        "Legal": {
          "Criteria": "Data breach suspected",
          "Format": "Detailed incident report",
          "Timing": "Within 4 hours"
        },
        "Customers": {
          "Criteria": "Service impact or data exposure",
          "Method": "Status page + Email",
          "Timing": "Per SLA agreements"
        }
      },
      "EvidenceCollection": {
        "MemoryDumps": {
          "Tool": "SSM Run Command",
          "Storage": "Isolated S3 bucket",
          "Encryption": "Forensic-specific KMS key"
        },
        "LogPreservation": {
          "Duration": "Extended to 7 years",
          "Immutability": "Object Lock enabled",
          "ChainOfCustody": "Automated documentation"
        },
        "ForensicImages": {
          "Method": "EBS snapshots",
          "Automation": "Lambda-triggered",
          "Tagging": "Incident ID + timestamp"
        },
        "NetworkCapture": {
          "VPCFlowLogs": "Enhanced capture",
          "PacketCapture": "Traffic mirroring",
          "Duration": "Incident + 48 hours"
        }
      }
    },
    "IncidentClassification": {
      "Severity": {
        "Critical": {
          "Definition": "Active data breach or system compromise",
          "ResponseTime": "< 15 minutes",
          "Team": "All security + executive"
        },
        "High": {
          "Definition": "Attempted breach or vulnerability",
          "ResponseTime": "< 1 hour",
          "Team": "Security team"
        },
        "Medium": {
          "Definition": "Policy violation or suspicious activity",
          "ResponseTime": "< 4 hours",
          "Team": "Security analyst"
        },
        "Low": {
          "Definition": "Minor anomaly or false positive",
          "ResponseTime": "< 24 hours",
          "Team": "Junior analyst"
        }
      }
    }
  }
}
```

インシデント発生時の初動対応を自動化し、被害の拡大を防止しながら証拠保全を実施します。段階的なエスカレーションにより、適切なレベルでの対応を確保します。

**インシデント対応プレイブック**

```yaml
# Incident Response Playbooks
IncidentPlaybooks:
  DataBreachResponse:
    InitialAssessment:
      - Step: "Confirm breach indicators"
        Automation: "GuardDuty finding analysis"
        Decision: "Proceed if confidence > 80%"
      - Step: "Identify affected systems"
        Automation: "Resource tagging and inventory"
        Output: "Affected resource list"
        
    Containment:
      - Step: "Isolate affected systems"
        Automation: "Security group lockdown"
        Verification: "Confirm isolation"
      - Step: "Preserve evidence"
        Automation: "Snapshot creation"
        Storage: "Forensic S3 bucket"
        
    Eradication:
      - Step: "Remove threat"
        Method: "Varies by threat type"
        Validation: "Threat scan"
      - Step: "Patch vulnerabilities"
        Automation: "SSM Patch Manager"
        Testing: "Staged rollout"
        
    Recovery:
      - Step: "Restore services"
        Method: "Blue-green deployment"
        Monitoring: "Enhanced for 48 hours"
      - Step: "Verify integrity"
        Checks: ["Data validation", "Service health"]
        
    PostIncident:
      - Step: "Lessons learned"
        Meeting: "Within 48 hours"
        Output: "Improvement actions"
      - Step: "Update procedures"
        Timeline: "Within 1 week"
        
  RansomwareResponse:
    Detection:
      - Indicators: ["File encryption", "Ransom notes", "C2 communication"]
      - AutoTrigger: "CloudWatch anomaly detection"
      
    ImmediateActions:
      - NetworkIsolation: "Instant via Lambda"
      - BackupProtection: "Disconnect backup systems"
      - SpreadPrevention: "Segment networks"
      
    Recovery:
      - BackupValidation: "Verify backup integrity"
      - SystemRestore: "From clean backups"
      - ValidationTests: "Data integrity checks"
```

プレイブックにより、インシデントタイプ別の標準化された対応手順を確立し、混乱を最小限に抑えます。

## 13. 災害復旧・事業継続のセキュリティ

### DR環境セキュリティ

**大阪リージョンDRセキュリティ**

```yaml
# DR Security Configuration
DRSecurity:
  PrimaryRegion: "ap-northeast-1"  # Tokyo
  DRRegion: "ap-northeast-3"       # Osaka
  
  SecurityReplication:
    - SecurityGroups: 
        Method: "CloudFormation StackSets"
        Sync: "Real-time via Lambda"
        Validation: "Daily consistency check"
    - NACLs: 
        Method: "Terraform state sync"
        Sync: "Every 4 hours"
        Drift: "Auto-correction"
    - WAFRules: 
        Method: "AWS Firewall Manager"
        Sync: "Centralized management"
        Testing: "Monthly validation"
    - KMSKeys: 
        Type: "Multi-region keys"
        Replication: "Automatic"
        Rotation: "Synchronized"
        
  AccessControl:
    - EmergencyAccess: 
        Procedure: "Break-glass"
        Approval: "2-person rule"
        Logging: "Enhanced audit trail"
        Duration: "Time-limited (4 hours)"
    - DRActivation: 
        Authorization: "Multi-person (CEO + CTO + CISO)"
        Method: "Hardware token + biometric"
        Validation: "Automated checklist"
    - SecurityValidation: 
        PreActivation: "Security posture verification"
        Checklist: "156-point validation"
        AutomatedTests: "Security control validation"
        
  DataProtection:
    - EncryptionInTransit: 
        Protocol: "TLS 1.3"
        Certificate: "Mutual authentication"
        Integrity: "HMAC-SHA256"
    - EncryptionAtRest: 
        Method: "Customer managed KMS"
        KeyAccess: "Cross-region permissions"
        Compliance: "Data residency maintained"
    - DataIntegrity: 
        Validation: "Continuous checksums"
        Monitoring: "Replication lag alerts"
        Recovery: "Point-in-time options"
        
  Monitoring:
    - SecurityEventReplication: 
        Latency: "< 1 minute"
        Method: "Kinesis cross-region"
        Deduplication: "Event correlation"
    - CrossRegionAlerting: 
        Channels: "Multi-region SNS"
        Escalation: "Region-aware routing"
        Failover: "Automatic rerouting"
    - ComplianceValidation: 
        Frequency: "Continuous"
        Reporting: "Unified dashboard"
        Certification: "Annual third-party"
```

DR環境でも本番環境と同等のセキュリティレベルを維持し、切り替え時のセキュリティギャップを防止します。Break-glass手順により、緊急時の迅速なアクセスを可能にしつつ、セキュリティを維持します。

**RTO/RPO セキュリティ考慮事項**

```json
{
  "DisasterRecoveryMetrics": {
    "RTO": {
      "Target": "4 hours",
      "SecurityValidation": "2 hours",
      "Components": {
        "NetworkSecurity": "30 minutes",
        "IAMReplication": "15 minutes",
        "DataDecryption": "45 minutes",
        "ServiceValidation": "90 minutes"
      }
    },
    "RPO": {
      "Target": "1 hour",
      "DataReplication": "Continuous",
      "SecurityLogs": "Real-time",
      "ConfigurationSync": "15 minutes"
    },
    "SecuritySpecificMetrics": {
      "KeyRotationSync": "< 5 minutes",
      "PolicyReplication": "< 1 minute",
      "SecurityGroupSync": "Real-time",
      "CompliancePosture": "99.9% match"
    },
    "TestingSchedule": {
      "FullDRTest": "Quarterly",
      "SecurityOnlyTest": "Monthly",
      "TabletopExercise": "Bi-annual",
      "AutomatedValidation": "Daily"
    }
  }
}
```

セキュリティ検証を含むRTO/RPOを設定し、災害時でもセキュリティを損なわない復旧を実現します。

## 14. コンプライアンス・ガバナンス

### 継続的コンプライアンス監視

**AWS Config統合**

```json
{
  "ConfigCompliance": {
    "ConfigRules": [
      {
        "RuleName": "encrypted-volumes",
        "Source": {
          "Owner": "AWS",
          "SourceIdentifier": "ENCRYPTED_VOLUMES"
        },
        "Scope": {
          "ComplianceResourceTypes": ["AWS::EC2::Volume"]
        },
        "EvaluationMode": "PROACTIVE",
        "MaximumExecutionFrequency": "TwentyFour_Hours"
      },
      {
        "RuleName": "s3-bucket-public-read-prohibited",
        "Source": {
          "Owner": "AWS",
          "SourceIdentifier": "S3_BUCKET_PUBLIC_READ_PROHIBITED"
        },
        "Scope": {
          "ComplianceResourceTypes": ["AWS::S3::Bucket"]
        },
        "EvaluationMode": "DETECTIVE"
      },
      {
        "RuleName": "iam-password-policy",
        "Source": {
          "Owner": "AWS",
          "SourceIdentifier": "IAM_PASSWORD_POLICY"
        },
        "InputParameters": {
          "RequireUppercaseCharacters": true,
          "RequireLowercaseCharacters": true,
          "RequireSymbols": true,
          "RequireNumbers": true,
          "MinimumPasswordLength": 12,
          "PasswordReusePrevention": 24,
          "MaxPasswordAge": 90
        }
      },
      {
        "RuleName": "custom-ami-compliance",
        "Source": {
          "Owner": "LAMBDA",
          "SourceIdentifier": "arn:aws:lambda:region:account:function:ami-compliance-checker"
        },
        "Scope": {
          "ComplianceResourceTypes": ["AWS::EC2::Instance"]
        },
        "InputParameters": {
          "ApprovedAMIs": ["ami-xxxxx", "ami-yyyyy"]
        }
      }
    ],
    "RemediationConfigurations": [
      {
        "ConfigRuleName": "encrypted-volumes",
        "TargetType": "SSM_DOCUMENT",
        "TargetId": "AWS-EnableEbsEncryptionByDefault",
        "TargetVersion": "1",
        "Parameters": {
          "AutomationAssumeRole": {
            "StaticValue": {
              "Values": ["arn:aws:iam::account:role/ConfigRemediationRole"]
            }
          }
        },
        "Automatic": true,
        "MaximumAutomaticAttempts": 3,
        "RetryAttemptSeconds": 600
      },
      {
        "ConfigRuleName": "s3-bucket-public-read-prohibited",
        "TargetType": "SSM_DOCUMENT", 
        "TargetId": "AWS-PublishSNSNotification",
        "Parameters": {
          "TopicArn": {
            "StaticValue": {
              "Values": ["arn:aws:sns:region:account:security-alerts"]
            }
          },
          "Message": {
            "StaticValue": {
              "Values": ["S3 bucket public access detected"]
            }
          }
        },
        "Automatic": false
      }
    ],
    "ConformancePacks": [
      {
        "Name": "operational-best-practices-for-hipaa",
        "TemplateS3Uri": "s3://aws-config-conformance-packs/operational-best-practices-for-hipaa.yaml",
        "Parameters": {
          "AccessKeysRotatedParamMaxAccessKeyAge": "90"
        }
      },
      {
        "Name": "security-best-practices",
        "TemplateBody": "Custom conformance pack template",
        "DeliveryS3Bucket": "technova-config-conformance"
      }
    ],
    "OrganizationAggregator": {
      "AggregatorName": "technova-org-compliance",
      "RoleArn": "arn:aws:iam::account:role/ConfigAggregatorRole",
      "AllAwsRegions": true,
      "OrganizationAggregationSource": {
        "AllMemberAccounts": true
      }
    }
  }
}
```

設定のドリフトを継続的に監視し、コンプライアンス違反を自動的に修復することで、常に安全な状態を維持します。コンフォーマンスパックにより、業界標準への準拠を簡素化します。

**コンプライアンススコアリング**

```yaml
# Compliance Scoring Framework
ComplianceScoring:
  ScoringMethodology:
    WeightedAverage:
      CriticalControls: 40%
      HighControls: 30%
      MediumControls: 20%
      LowControls: 10%
      
  ControlCategories:
    AccessManagement:
      Weight: 25%
      Controls:
        - MFAEnabled: Critical
        - LeastPrivilege: High
        - RegularAccessReview: Medium
        
    DataProtection:
      Weight: 30%
      Controls:
        - EncryptionAtRest: Critical
        - EncryptionInTransit: Critical
        - DataClassification: High
        
    NetworkSecurity:
      Weight: 20%
      Controls:
        - NetworkSegmentation: High
        - FirewallRules: High
        - VPNAccess: Medium
        
    Monitoring:
      Weight: 15%
      Controls:
        - LoggingEnabled: Critical
        - RealTimeAlerts: High
        - RegularReview: Medium
        
    IncidentResponse:
      Weight: 10%
      Controls:
        - ResponsePlan: High
        - RegularTesting: Medium
        - PostIncidentReview: Low
        
  Thresholds:
    Excellent: ">= 95%"
    Good: ">= 85%"
    Acceptable: ">= 75%"
    NeedsImprovement: "< 75%"
    
  Reporting:
    Frequency: "Weekly"
    Audience:
      - SecurityTeam: "Detailed technical report"
      - Management: "Executive dashboard"
      - Auditors: "Compliance attestation"
```

コンプライアンススコアリングにより、セキュリティ態勢を定量的に評価し、改善点を明確化します。

### 定期的セキュリティ評価

**セキュリティ評価フレームワーク**

```yaml
# Security Assessment Framework
SecurityAssessment:
  VulnerabilityAssessment:
    - Frequency: "Monthly"
    - Scope: 
        Production: "All systems"
        Development: "External-facing only"
        Network: "Full infrastructure"
    - Tools: 
        - AWS Inspector:
            Assessments: ["Network", "Host", "Application"]
            RulePackages: ["CVE", "CIS", "Security Best Practices"]
        - Third-party:
            Scanner: "Qualys/Tenable"
            Coverage: "OS, Applications, Databases"
        - Custom:
            Scripts: "Organization-specific checks"
            Focus: "Business logic vulnerabilities"
    - Reporting: 
        Format: "CVSS scored findings"
        Dashboard: "Real-time vulnerability tracking"
        Remediation: "Automated ticket creation"
    
  PenetrationTesting:
    - Frequency: "Quarterly"
    - Scope: 
        External: "Internet-facing systems"
        Internal: "Critical internal systems"
        Physical: "Data center access"
    - Methodology:
        Framework: "PTES/OWASP"
        Phases: ["Recon", "Scanning", "Exploitation", "Post-exploit"]
        Rules: "Agreed rules of engagement"
    - Authorization: 
        AWS: "Penetration testing approval form"
        Internal: "Executive sign-off"
        Scope: "Clearly defined boundaries"
    - Reporting: 
        Technical: "Detailed exploit chains"
        Executive: "Risk-based summary"
        Remediation: "Prioritized action plan"
    
  ComplianceAudit:
    - Frequency: "Annual"
    - Standards: 
        - ISO27001:
            Scope: "Full ISMS"
            Auditor: "Accredited certification body"
        - SOC2:
            Type: "Type II"
            Period: "12 months"
        - PCI-DSS:
            Level: "Level 2"
            Method: "SAQ + Quarterly scans"
    - Preparation:
        EvidenceCollection: "Automated via compliance tool"
        Documentation: "Policy and procedure review"
        Training: "Staff awareness sessions"
    - Remediation: 
        Timeline: "30-60-90 day plans"
        Tracking: "JIRA integration"
        Validation: "Follow-up assessment"
    
  SecurityMetrics:
    - MeanTimeToDetection: 
        Target: "< 5 minutes"
        Measurement: "From event to alert"
        Improvement: "ML-based detection"
    - MeanTimeToResponse: 
        Target: "< 30 minutes"
        Measurement: "From alert to containment"
        Automation: "Playbook execution"
    - SecurityIncidents: 
        Tracking: "Monthly trend analysis"
        Categories: "By severity and type"
        RootCause: "Post-incident analysis"
    - ComplianceScore: 
        Target: "99.5%"
        Calculation: "Weighted control effectiveness"
        Reporting: "Executive dashboard"
```

定期的な評価により、セキュリティ態勢の継続的な改善と高いセキュリティレベルの維持を実現します。複数の評価手法を組み合わせることで、包括的な視点でのセキュリティ検証を行います。

## 15. セキュリティ運用・管理

### 実装対象サービス

**AWS Security Hub（セキュリティ統合管理）**
- 全120アカウントのセキュリティ状況を一元的に可視化し、優先順位付けされた対応を実現します。単一のダッシュボードで組織全体のセキュリティ態勢を把握でき、効率的な管理が可能になります。
- AWS標準に加え、業界標準（CIS、PCI DSS）への準拠状況を継続的に監視します。コンプライアンス違反は自動的に検出され、修復アクションが提案されるため、常に高いセキュリティレベルを維持できます。

**Amazon GuardDuty（脅威検知）**
- 機械学習による異常検知で、既知・未知の脅威を早期発見します。VPCフローログ、DNSログ、CloudTrailイベントを分析し、通常とは異なるパターンを検出することで、高度な攻撃も見逃しません。
- S3、EKS、EC2の各データソースを有効化し、包括的な監視を実現します。マルウェアスキャン機能により、実行中のワークロードからの脅威も検出し、侵害の拡大を防止します。

**AWS Config（コンプライアンス監視）**
- リソース設定の変更を追跡し、承認されていない変更を即座に検出します。設定履歴により、いつ、誰が、何を変更したかを完全に追跡でき、問題の原因究明を迅速に行えます。
- 自動修復アクションにより、設定のドリフトを防止します。例えば、暗号化が無効化されたEBSボリュームを自動的に再暗号化し、セキュリティポリシーへの準拠を維持します。

**Amazon CloudWatch（メトリクス・アラート）**
- セキュリティメトリクスの収集と可視化により、KPI管理を実現します。MTTD（平均検出時間）、MTTR（平均対応時間）などの重要指標を継続的に測定し、改善効果を定量的に把握できます。
- 異常値検出により、通常と異なるパターンを早期に発見します。機械学習ベースの異常検出により、閾値設定の手間を削減しながら、より精度の高い検出を実現します。

**AWS Systems Manager（運用自動化）**
- パッチ管理、設定管理、運用タスクの自動化により、人的ミスを削減します。定期的なパッチ適用やコンプライアンスチェックを自動化し、セキュリティレベルを一定に保ちます。
- Run Commandにより、緊急時の対応も迅速に実行できます。侵害されたインスタンスの隔離や、セキュリティ設定の一括変更などを安全に実行できます。

### Terraform実装コード

```hcl
# Security Hub の組織レベル設定
resource "aws_securityhub_account" "main" {
  enable_default_standards = true
  
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_securityhub_standards_subscription" "aws_foundational" {
  standards_arn = "arn:aws:securityhub:::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.main]
}

resource "aws_securityhub_standards_subscription" "cis" {
  standards_arn = "arn:aws:securityhub:::standards/cis-aws-foundations-benchmark/v/1.2.0"
  depends_on    = [aws_securityhub_account.main]
}

resource "aws_securityhub_standards_subscription" "pci_dss" {
  standards_arn = "arn:aws:securityhub:::standards/pci-dss/v/3.2.1"
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
    Purpose = "Vendor Security Requirements"
    LastUpdated = "2024-01-01"
  }
}
```