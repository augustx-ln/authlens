use super::LiveEvent;

const FILE_HEADER_SIZE: usize = 4096;
const CHUNK_SIZE: usize = 65_536;
const CHUNK_HEADER_SIZE: usize = 512;
const FILETIME_EPOCH: u64 = 116_444_736_000_000_000;
const PROVIDER: &str = "AuthLens-LiveLab";
const PROVIDER_GUID: &str = "{B549F3F2-59F8-48BC-8B95-3E6C08E29472}";
const TEMPLATE_GUID: [u8; 16] = [
    0xfd, 0xb5, 0x36, 0x4f, 0x9f, 0x6b, 0xd3, 0x43, 0xb2, 0xad, 0x0b, 0x8a, 0x6f, 0x26, 0xf4, 0x09,
];

pub fn encode(events: &[LiveEvent]) -> Result<Vec<u8>, String> {
    let mut chunks = Vec::new();
    let mut records = Vec::new();
    let mut offset = CHUNK_HEADER_SIZE;

    for (index, event) in events.iter().rev().enumerate() {
        let record_id = index as u64 + 1;
        let mut record = event_record(event, record_id, offset)?;
        if offset + record.len() > CHUNK_SIZE {
            if records.is_empty() {
                return Err("An event is too large for an EVTX chunk".into());
            }
            chunks.push(chunk(&records, offset));
            records.clear();
            offset = CHUNK_HEADER_SIZE;
            record = event_record(event, record_id, offset)?;
            if offset + record.len() > CHUNK_SIZE {
                return Err("An event is too large for an EVTX chunk".into());
            }
        }
        offset += record.len();
        records.push((record_id, record));
    }

    if !records.is_empty() {
        chunks.push(chunk(&records, offset));
    }
    if chunks.is_empty() {
        chunks.push(chunk(&[], CHUNK_HEADER_SIZE));
    }
    if chunks.len() > u16::MAX as usize {
        return Err("The EVTX export contains too many chunks".into());
    }

    let mut file = vec![0; FILE_HEADER_SIZE];
    file[..8].copy_from_slice(b"ElfFile\0");
    put_u64(&mut file, 8, 0);
    put_u64(&mut file, 16, chunks.len() as u64 - 1);
    put_u64(&mut file, 24, events.len() as u64 + 1);
    put_u32(&mut file, 32, 128);
    put_u16(&mut file, 36, 1);
    put_u16(&mut file, 38, 3);
    put_u16(&mut file, 40, FILE_HEADER_SIZE as u16);
    put_u16(&mut file, 42, chunks.len() as u16);
    let header_crc = crc32(&file[..120]);
    put_u32(&mut file, 124, header_crc);
    for chunk in chunks {
        file.extend_from_slice(&chunk);
    }
    Ok(file)
}

fn chunk(records: &[(u64, Vec<u8>)], free_offset: usize) -> Vec<u8> {
    let mut data = vec![0; CHUNK_SIZE];
    data[..8].copy_from_slice(b"ElfChnk\0");
    let first_id = records.first().map_or(0, |record| record.0);
    let last_id = records.last().map_or(0, |record| record.0);
    let mut offset = CHUNK_HEADER_SIZE;
    let mut last_record_offset = 0;
    for (_, record) in records {
        last_record_offset = offset;
        data[offset..offset + record.len()].copy_from_slice(record);
        offset += record.len();
    }
    put_u64(&mut data, 8, first_id);
    put_u64(&mut data, 16, last_id);
    put_u64(&mut data, 24, first_id);
    put_u64(&mut data, 32, last_id);
    put_u32(&mut data, 40, 128);
    put_u32(&mut data, 44, last_record_offset as u32);
    put_u32(&mut data, 48, free_offset as u32);
    let records_crc = crc32(&data[CHUNK_HEADER_SIZE..free_offset]);
    put_u32(&mut data, 52, records_crc);
    let header_crc = crc32_parts(&[&data[..120], &data[128..CHUNK_HEADER_SIZE]]);
    put_u32(&mut data, 124, header_crc);
    data
}

fn event_record(event: &LiveEvent, record_id: u64, chunk_offset: usize) -> Result<Vec<u8>, String> {
    let xml = BinXml::new(chunk_offset + 24).event(event, record_id)?;
    let mut size = 24 + xml.len() + 4;
    size += (8 - size % 8) % 8;
    if size > u32::MAX as usize {
        return Err("An EVTX record is too large".into());
    }
    let mut record = vec![0; size];
    record[..4].copy_from_slice(b"**\0\0");
    put_u32(&mut record, 4, size as u32);
    put_u64(&mut record, 8, record_id);
    put_u64(
        &mut record,
        16,
        FILETIME_EPOCH.saturating_add(event.at_ms.saturating_mul(10_000)),
    );
    record[24..24 + xml.len()].copy_from_slice(&xml);
    put_u32(&mut record, size - 4, size as u32);
    Ok(record)
}

struct BinXml {
    data: Vec<u8>,
    chunk_offset: usize,
    values: Vec<String>,
}

impl BinXml {
    fn new(chunk_offset: usize) -> Self {
        Self {
            data: Vec::new(),
            chunk_offset,
            values: Vec::new(),
        }
    }

    fn event(mut self, event: &LiveEvent, record_id: u64) -> Result<Vec<u8>, String> {
        self.data
            .extend_from_slice(&[0x0f, 0x01, 0x01, 0x00, 0x0c, 0x01]);
        let template_id = crc32(format!("{PROVIDER}:{}", event_id(event)).as_bytes());
        let template_offset = self.chunk_offset + self.data.len() + 8;
        push_u32(&mut self.data, template_id);
        push_u32(
            &mut self.data,
            u32::try_from(template_offset).map_err(|_| "EVTX template offset overflow")?,
        );

        let template_start = self.data.len();
        self.data.resize(template_start + 24, 0);
        let body_start = self.data.len();
        self.element(
            "Event",
            &[(
                "xmlns",
                "http://schemas.microsoft.com/win/2004/08/events/event".into(),
            )],
            |xml| {
                xml.system(event, record_id)?;
                xml.event_data(event)
            },
        )?;
        self.data.push(0);
        let body_size = (self.data.len() - body_start) as u32;
        put_u32(&mut self.data, template_start, 0);
        self.data[template_start + 4..template_start + 20].copy_from_slice(&TEMPLATE_GUID);
        put_u32(&mut self.data, template_start + 20, body_size);
        self.substitution_table()?;
        Ok(self.data)
    }

    fn system(&mut self, event: &LiveEvent, record_id: u64) -> Result<(), String> {
        self.element("System", &[], |xml| {
            xml.empty_element(
                "Provider",
                &[("Name", PROVIDER.into()), ("Guid", PROVIDER_GUID.into())],
            )?;
            xml.text_element("EventID", &event_id(event).to_string(), &[])?;
            xml.text_element("Version", "0", &[])?;
            xml.text_element("Level", "4", &[])?;
            xml.text_element("Task", "0", &[])?;
            xml.text_element("Opcode", "0", &[])?;
            xml.text_element("Keywords", "0x0000000000000000", &[])?;
            xml.empty_element("TimeCreated", &[("SystemTime", system_time(event.at_ms))])?;
            xml.text_element("EventRecordID", &record_id.to_string(), &[])?;
            xml.empty_element("Correlation", &[])?;
            xml.empty_element(
                "Execution",
                &[("ProcessID", "0".into()), ("ThreadID", "0".into())],
            )?;
            xml.text_element("Channel", "Application", &[])?;
            xml.text_element("Computer", "AUTHLENS-LAB", &[])?;
            xml.empty_element("Security", &[])
        })
    }

    fn event_data(&mut self, event: &LiveEvent) -> Result<(), String> {
        let is_http = event.kind == "http";
        let values = [
            (
                "EventType",
                if is_http {
                    "HTTP request"
                } else {
                    "TCP connection"
                },
            ),
            ("SourceAddress", event.source.as_str()),
            ("DestinationPort", ""),
            ("Protocol", "TCP"),
            ("Detail", ""),
            ("ResponseStatus", ""),
        ];
        let mut fields = values.map(|(name, value)| (name, value.to_owned()));
        fields[2].1 = event.port.to_string();
        fields[4].1 = event.detail.clone();
        if is_http {
            fields[5].1 = event
                .status
                .map_or_else(String::new, |status| status.to_string());
        }
        self.element("EventData", &[], |xml| {
            for (name, value) in &fields {
                xml.text_element("Data", value, &[("Name", (*name).into())])?;
            }
            Ok(())
        })
    }

    fn element(
        &mut self,
        name: &str,
        attrs: &[(&str, String)],
        children: impl FnOnce(&mut Self) -> Result<(), String>,
    ) -> Result<(), String> {
        let start = self.start(name, attrs)?;
        self.data.push(0x02);
        children(self)?;
        self.data.push(0x04);
        self.patch_data_size(start)
    }

    fn text_element(
        &mut self,
        name: &str,
        value: &str,
        attrs: &[(&str, String)],
    ) -> Result<(), String> {
        let start = self.start(name, attrs)?;
        self.data.push(0x02);
        self.value(value)?;
        self.data.push(0x04);
        self.patch_data_size(start)
    }

    fn empty_element(&mut self, name: &str, attrs: &[(&str, String)]) -> Result<(), String> {
        self.start(name, attrs)?;
        self.data.push(0x03);
        Ok(())
    }

    fn start(&mut self, name: &str, attrs: &[(&str, String)]) -> Result<usize, String> {
        let start = self.data.len();
        self.data.push(if attrs.is_empty() { 0x01 } else { 0x41 });
        push_u16(&mut self.data, u16::MAX);
        push_u32(&mut self.data, 0);
        let name_offset = self.chunk_offset + self.data.len() + 4;
        push_u32(
            &mut self.data,
            u32::try_from(name_offset).map_err(|_| "EVTX name offset overflow")?,
        );
        self.write_name(name)?;
        if !attrs.is_empty() {
            let size_at = self.data.len();
            push_u32(&mut self.data, 0);
            let attr_start = self.data.len();
            for (index, (key, value)) in attrs.iter().enumerate() {
                self.data
                    .push(if index + 1 == attrs.len() { 0x06 } else { 0x46 });
                let attr_name_offset = self.chunk_offset + self.data.len() + 4;
                push_u32(
                    &mut self.data,
                    u32::try_from(attr_name_offset)
                        .map_err(|_| "EVTX attribute offset overflow")?,
                );
                self.write_name(key)?;
                self.value(value)?;
            }
            self.patch_u32(size_at, (self.data.len() - attr_start) as u32);
        }
        Ok(start)
    }

    fn write_name(&mut self, name: &str) -> Result<(), String> {
        let units: Vec<u16> = name.encode_utf16().collect();
        let length = u16::try_from(units.len()).map_err(|_| "EVTX XML name is too long")?;
        push_u32(&mut self.data, 0);
        push_u16(&mut self.data, 0);
        push_u16(&mut self.data, length);
        for unit in units {
            push_u16(&mut self.data, unit);
        }
        push_u16(&mut self.data, 0);
        Ok(())
    }

    fn value(&mut self, value: &str) -> Result<(), String> {
        let index = u16::try_from(self.values.len()).map_err(|_| "Too many EVTX values")?;
        self.values.push(value.to_owned());
        self.data.push(0x0d);
        push_u16(&mut self.data, index);
        self.data.push(0x01);
        Ok(())
    }

    fn patch_data_size(&mut self, start: usize) -> Result<(), String> {
        let size = u32::try_from(self.data.len() - (start + 7))
            .map_err(|_| "EVTX XML element is too large")?;
        self.patch_u32(start + 3, size);
        Ok(())
    }

    fn patch_u32(&mut self, offset: usize, value: u32) {
        self.data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn substitution_table(&mut self) -> Result<(), String> {
        push_u32(&mut self.data, self.values.len() as u32);
        let encoded: Vec<Vec<u8>> = self
            .values
            .iter()
            .map(|value| value.encode_utf16().flat_map(u16::to_le_bytes).collect())
            .collect();
        for value in &encoded {
            let length = u16::try_from(value.len()).map_err(|_| "EVTX value is too long")?;
            push_u16(&mut self.data, length);
            self.data.extend_from_slice(&[0x01, 0x00]);
        }
        for value in encoded {
            self.data.extend_from_slice(&value);
        }
        Ok(())
    }
}

fn event_id(event: &LiveEvent) -> u32 {
    if event.kind == "http" { 1001 } else { 1000 }
}

fn system_time(at_ms: u64) -> String {
    let seconds = (at_ms / 1000) as i64;
    let milliseconds = at_ms % 1000;
    let days = seconds.div_euclid(86_400);
    let day_seconds = seconds.rem_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 }.div_euclid(146_097);
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    format!(
        "{year:04}-{:02}-{day:02}T{:02}:{:02}:{:02}.{milliseconds:03}Z",
        month,
        day_seconds / 3_600,
        day_seconds % 3_600 / 60,
        day_seconds % 60
    )
}

fn put_u16(data: &mut [u8], offset: usize, value: u16) {
    data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn push_u16(data: &mut Vec<u8>, value: u16) {
    data.extend_from_slice(&value.to_le_bytes());
}

fn put_u32(data: &mut [u8], offset: usize, value: u32) {
    data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn push_u32(data: &mut Vec<u8>, value: u32) {
    data.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(data: &mut [u8], offset: usize, value: u64) {
    data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn crc32(bytes: &[u8]) -> u32 {
    crc32_parts(&[bytes])
}

fn crc32_parts(parts: &[&[u8]]) -> u32 {
    let mut crc = u32::MAX;
    for bytes in parts {
        for byte in *bytes {
            crc ^= u32::from(*byte);
            for _ in 0..8 {
                crc = if crc & 1 == 1 {
                    (crc >> 1) ^ 0xedb8_8320
                } else {
                    crc >> 1
                };
            }
        }
    }
    !crc
}
