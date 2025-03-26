with cdps_aip_inventory as (
    select * from "aip1b-data"
    union select * from "aip2b-data"
    union select * from "aip3b-data"
    union select * from "aip4b-data"
    union select * from "aip5b-data"
),
aip_files as (
    select * from cdps_aip_inventory
    where key like %(s3_key_prefix)s
    -- the following utilizes the hive 'dt' partition, limiting data scanned
    and (
        parse_datetime(dt, 'yyyy-MM-dd-HH-mm')
        between date_add('day', -3, current_timestamp) and current_timestamp
    )
),
latest_file_dates as (
    select
        key,
        max(last_modified_date) as max_date
    from aip_files
    where is_latest = true and is_delete_marker = false
    group by key
)
select
    af.key,
    af.checksum_algorithm
from aip_files af
inner join latest_file_dates lf on
    af.key = lf.key and
    af.last_modified_date = lf.max_date
;