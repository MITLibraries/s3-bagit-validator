with cdps_aip_inventory as (
    select * from "aip1b-data"
    union all select * from "aip2b-data"
    union all select * from "aip3b-data"
    union all select * from "aip4b-data"
    union all select * from "aip5b-data"
),
date_ordered_files as (
    select
        *,
        row_number() over (partition by key order by last_modified_date desc) as rn
    from cdps_aip_inventory
    where key like %(s3_key_prefix)s
    and (
        parse_datetime(dt, 'yyyy-MM-dd-HH-mm')
        between date_add('day', -3, current_timestamp) and current_timestamp
    )
)
select
    key,
    checksum_algorithm
from date_ordered_files
where rn = 1
and is_latest = true
and is_delete_marker = false