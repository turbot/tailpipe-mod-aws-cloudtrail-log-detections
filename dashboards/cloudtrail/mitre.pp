card "base_card" {
  width = 3
}

dashboard "cloudtrail_log_mitre_attack" {

  title         = "CloudTrail Logs MITRE ATT&CK Coverage"
  #documentation = file("./dashboards/ec2/docs/ec2_instance_detail.md")

  tags = merge(local.cloudtrail_log_common_tags, {
    type = "Report"
  })


  container {
    title = "Initial Access"

    //text { value = "Placeholder" }

    container {
      title = "Initial Access"
      width = 12

      container {

        table {
          sql = "select * from(values('High', 2), ('Medium', 3), ('Low', 0)) as t(priority, count)"
          width = 2
          title = "Content Injection"
        }

        table {
          sql = "select * from(values('High', 0), ('Medium', 5), ('Low', 0)) as t(priority, count)"
          width = 2
          title = "Drive-by Compromise"
        }

        table {
          sql = "select * from(values('High', 5), ('Medium', 0), ('Low', 20)) as t(priority, count)"
          width = 2
          title = "Exploit Public-Facing Application"
        }
      }

      card {
        base = card.base_card
        sql  = "select 1 as 'Content Injection'"
        type = "alert"
      }
      card {
        sql  = "select 2 as 'Drive-by Compromise'"
        base = card.base_card
        type = "alert"
      }
      card {
        sql  = "select 5 as 'Exploit Public-Facing Application'"
        base = card.base_card
        type = "alert"
      }
      card {
        sql  = "select 0 as 'External Remote Services'"
        base = card.base_card
        type = "ok"
      }
      card {
        sql  = "select 10 as 'Hardware Additions'"
        base = card.base_card
        type = "alert"
      }
      card {
        sql  = "select 22 as 'Phishing'"
        base = card.base_card
        type = "alert"
      }
      card {
        sql  = "select 4 as 'Replication Trhough Removable Media'"
        base = card.base_card
        type = "alert"
      }
      card {
        sql  = "select 2 as 'Supply Chain Compromise'"
        base = card.base_card
        type = "alert"
      }
      card {
        sql  = "select 0 as 'Trusted Relationship'"
        base = card.base_card
        type = "ok"
      }
      card {
        sql  = "select 9 as 'Valid Accounts'"
        base = card.base_card
        type = "alert"
      }
    }
  }

  container {
    title = "Execution"

    //text { value = "Placeholder" }

    container {
      width = 12

      card {
        sql  = "select 1 as 'Cloud Administration Command'"
        base = card.base_card
        type = "alert"
      }
      card {
        sql  = "select 2 as 'Command and Scripting Interpreter'"
        base = card.base_card
        type = "alert"
      }
      card {
        sql  = "select 5 as 'Container Administration Command'"
        base = card.base_card
        type = "alert"
      }
      card {
        sql  = "select 0 as 'Deploy Container'"
        base = card.base_card
        type = "ok"
      }
      card {
        sql  = "select 10 as 'Explotation for Client Execution'"
        base = card.base_card
        type = "alert"
      }
      card {
        sql  = "select 22 as 'Inter-Process Communication'"
        base = card.base_card
        type = "alert"
      }
      card {
        sql  = "select 4 as 'Native API'"
        base = card.base_card
        type = "alert"
      }
      card {
        sql  = "select 2 as 'Scheduled Task/Job'"
        base = card.base_card
        type = "alert"
      }
      card {
        sql  = "select 0 as 'Serverless Execution'"
        base = card.base_card
        type = "ok"
      }
      card {
        sql  = "select 9 as 'Shared Modules'"
        base = card.base_card
        type = "alert"
      }
    }
  }

}
