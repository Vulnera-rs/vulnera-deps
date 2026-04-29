use super::traits::{FilePattern, PackageFileParser, ParseResult, SourceType};
use super::version_extractor;
use crate::application::errors::ParseError;
use crate::domain::vulnerability::{
    entities::Package,
    value_objects::{Ecosystem, Version},
};
use quick_xml::Reader;
use quick_xml::events::Event;

/// Parser for legacy NuGet packages.config files.
/// Example:
/// <?xml version="1.0" encoding="utf-8"?>
/// <packages>
///   <package id="Newtonsoft.Json" version="12.0.3" targetFramework="net472" />
///   <package id="Serilog" version="2.10.0" />
/// </packages>
pub struct NuGetPackagesConfigParser;

impl Default for NuGetPackagesConfigParser {
    fn default() -> Self {
        Self::new()
    }
}

impl NuGetPackagesConfigParser {
    pub fn new() -> Self {
        Self
    }

    fn parse_packages_config(&self, content: &str) -> Result<Vec<Package>, ParseError> {
        let mut packages = Vec::new();

        let mut reader = Reader::from_str(content);
        reader.config_mut().trim_text(true);

        let mut buf = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                    let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    if name.eq_ignore_ascii_case("package") {
                        let mut id: Option<String> = None;
                        let mut version: Option<String> = None;

                        for attr in e.attributes().flatten() {
                            let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                            let val = reader
                                .decoder()
                                .decode(&attr.value)
                                .unwrap_or_default()
                                .trim()
                                .to_string();

                            match key.as_str() {
                                "id" => id = Some(val),
                                "version" => version = Some(val),
                                _ => {}
                            }
                        }

                        if let Some(pkg_name) = id {
                            let ver = match version {
                                Some(raw_ver) => match version_extractor::nuget_locked(&raw_ver)? {
                                    Some(v) => v,
                                    None => continue,
                                },
                                None => Version::parse("0.0.0").unwrap(),
                            };

                            let pkg = Package::new(pkg_name, ver, Ecosystem::NuGet)
                                .map_err(|e| ParseError::MissingField { field: e })?;
                            packages.push(pkg);
                        }
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => {
                    return Err(ParseError::MissingField {
                        field: format!("XML parse error: {}", e),
                    });
                }
                _ => {}
            }
            buf.clear();
        }

        Ok(packages)
    }
}

impl PackageFileParser for NuGetPackagesConfigParser {
    fn parse(&self, content: &str) -> Result<ParseResult, ParseError> {
        let packages = self.parse_packages_config(content)?;
        Ok(ParseResult {
            packages,
            dependencies: Vec::new(),
            source_type: SourceType::LockFile,
        })
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::NuGet
    }

    fn patterns(&self) -> &[FilePattern] {
        &[FilePattern::Name("packages.config")]
    }
}

/// Parser for SDK-style project files (.csproj, .fsproj, .vbproj) with <PackageReference>
/// Examples:
/// <PackageReference Include="Newtonsoft.Json" Version="13.0.1" />
/// <PackageReference Include="Serilog">
///   <Version>2.12.0</Version>
/// </PackageReference>
pub struct NuGetProjectXmlParser;

impl Default for NuGetProjectXmlParser {
    fn default() -> Self {
        Self::new()
    }
}

impl NuGetProjectXmlParser {
    pub fn new() -> Self {
        Self
    }

    fn parse_project_xml(&self, content: &str) -> Result<Vec<Package>, ParseError> {
        let mut packages = Vec::new();

        let mut reader = Reader::from_str(content);
        reader.config_mut().trim_text(true);

        let mut buf = Vec::new();

        let mut in_package_ref = false;
        let mut current_name: Option<String> = None;
        let mut current_version: Option<String> = None;
        let mut in_version_child = false;

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(e)) => {
                    let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    if tag.eq_ignore_ascii_case("PackageReference") {
                        in_package_ref = true;
                        current_name = None;
                        current_version = None;

                        for attr in e.attributes().flatten() {
                            let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                            let val = reader
                                .decoder()
                                .decode(&attr.value)
                                .unwrap_or_default()
                                .trim()
                                .to_string();

                            match key.as_str() {
                                "Include" => current_name = Some(val),
                                "Version" if current_version.is_none() => {
                                    current_version = Some(val)
                                }
                                "VersionOverride" => current_version = Some(val),
                                _ => {}
                            }
                        }
                    } else if tag.eq_ignore_ascii_case("PackageVersion") {
                        let mut name: Option<String> = None;
                        let mut ver: Option<String> = None;
                        for attr in e.attributes().flatten() {
                            let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                            let val = reader
                                .decoder()
                                .decode(&attr.value)
                                .unwrap_or_default()
                                .trim()
                                .to_string();
                            match key.as_str() {
                                "Include" => name = Some(val),
                                "Version" => ver = Some(val),
                                _ => {}
                            }
                        }
                        if let Some(pkg_name) = name
                            && let Some(raw_ver) = ver
                                && let Some(v) = version_extractor::nuget_locked(&raw_ver)? {
                                    let pkg = Package::new(pkg_name, v, Ecosystem::NuGet)
                                        .map_err(|e| ParseError::MissingField { field: e })?;
                                    packages.push(pkg);
                                }
                    } else if in_package_ref && tag.eq_ignore_ascii_case("Version") {
                        in_version_child = true;
                    }
                }
                Ok(Event::Empty(e)) => {
                    let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    if tag.eq_ignore_ascii_case("PackageReference") {
                        // Self-closing PackageReference
                        let mut name_attr: Option<String> = None;
                        let mut version_attr: Option<String> = None;

                        for attr in e.attributes().flatten() {
                            let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                            let val = reader
                                .decoder()
                                .decode(&attr.value)
                                .unwrap_or_default()
                                .trim()
                                .to_string();
                            match key.as_str() {
                                "Include" => name_attr = Some(val),
                                "Version" if version_attr.is_none() => version_attr = Some(val),
                                "VersionOverride" => version_attr = Some(val),
                                _ => {}
                            }
                        }

                        if let Some(pkg_name) = name_attr
                            && let Some(raw_ver) = version_attr
                                && let Some(v) = version_extractor::nuget_locked(&raw_ver)? {
                                    let pkg = Package::new(pkg_name, v, Ecosystem::NuGet)
                                        .map_err(|e| ParseError::MissingField { field: e })?;
                                    packages.push(pkg);
                                }
                    } else if tag.eq_ignore_ascii_case("PackageVersion") {
                        let mut name_attr: Option<String> = None;
                        let mut version_attr: Option<String> = None;
                        for attr in e.attributes().flatten() {
                            let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                            let val = reader
                                .decoder()
                                .decode(&attr.value)
                                .unwrap_or_default()
                                .trim()
                                .to_string();
                            match key.as_str() {
                                "Include" => name_attr = Some(val),
                                "Version" => version_attr = Some(val),
                                _ => {}
                            }
                        }
                        if let Some(pkg_name) = name_attr
                            && let Some(raw_ver) = version_attr
                                && let Some(v) = version_extractor::nuget_locked(&raw_ver)? {
                                    let pkg = Package::new(pkg_name, v, Ecosystem::NuGet)
                                        .map_err(|e| ParseError::MissingField { field: e })?;
                                    packages.push(pkg);
                                }
                    }
                }
                Ok(Event::Text(t)) if in_package_ref && in_version_child => {
                    let txt = reader
                        .decoder()
                        .decode(t.as_ref())
                        .unwrap_or_default()
                        .trim()
                        .to_string();
                    if !txt.is_empty() {
                        current_version = Some(txt);
                    }
                }
                Ok(Event::Text(_)) => {}
                Ok(Event::End(e)) => {
                    let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    if tag.eq_ignore_ascii_case("Version") && in_package_ref {
                        in_version_child = false;
                    } else if tag.eq_ignore_ascii_case("PackageReference") && in_package_ref {
                        // Finalize this package ref
                        if let Some(pkg_name) = current_name.take()
                            && let Some(raw_ver) = current_version.take()
                                && let Some(v) = version_extractor::nuget_locked(&raw_ver)? {
                                    let pkg = Package::new(pkg_name, v, Ecosystem::NuGet)
                                        .map_err(|e| ParseError::MissingField { field: e })?;
                                    packages.push(pkg);
                                }
                        in_package_ref = false;
                        in_version_child = false;
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => {
                    return Err(ParseError::MissingField {
                        field: format!("XML parse error: {}", e),
                    });
                }
                _ => {}
            }
            buf.clear();
        }

        Ok(packages)
    }
}

impl PackageFileParser for NuGetProjectXmlParser {
    fn parse(&self, content: &str) -> Result<ParseResult, ParseError> {
        let packages = self.parse_project_xml(content)?;
        Ok(ParseResult {
            packages,
            dependencies: Vec::new(),
            source_type: SourceType::Manifest,
        })
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::NuGet
    }

    fn patterns(&self) -> &[FilePattern] {
        &[
            FilePattern::Extension("csproj"),
            FilePattern::Extension("fsproj"),
            FilePattern::Extension("vbproj"),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packages_config_parser() {
        let parser = NuGetPackagesConfigParser::new();
        let content = r#"
<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="Newtonsoft.Json" version="12.0.3" targetFramework="net472" />
  <package id="Serilog" version="[2.10.0,3.0.0)" />
  <package id="NoVersion" />
</packages>
"#;

        let result = parser.parse(content).unwrap();
        assert_eq!(result.packages.len(), 3);

        let nj = result
            .packages
            .iter()
            .find(|p| p.name == "Newtonsoft.Json")
            .unwrap();
        assert_eq!(nj.version, Version::parse("12.0.3").unwrap());

        let serilog = result
            .packages
            .iter()
            .find(|p| p.name == "Serilog")
            .unwrap();
        assert_eq!(serilog.version, Version::parse("2.10.0").unwrap());

        let nov = result
            .packages
            .iter()
            .find(|p| p.name == "NoVersion")
            .unwrap();
        assert_eq!(nov.version, Version::parse("0.0.0").unwrap());
    }

    #[test]
    fn test_project_xml_parser() {
        let parser = NuGetProjectXmlParser::new();
        let content = r#"
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.1" />
    <PackageReference Include="Serilog">
      <Version>2.12.0</Version>
    </PackageReference>
    <PackageReference Include="WeirdVersion" Version="[1.2.3, 2.0.0)" />
  </ItemGroup>
</Project>
"#;

        let result = parser.parse(content).unwrap();
        assert_eq!(result.packages.len(), 3);

        let nj = result
            .packages
            .iter()
            .find(|p| p.name == "Newtonsoft.Json")
            .unwrap();
        assert_eq!(nj.version, Version::parse("13.0.1").unwrap());

        let serilog = result
            .packages
            .iter()
            .find(|p| p.name == "Serilog")
            .unwrap();
        assert_eq!(serilog.version, Version::parse("2.12.0").unwrap());

        let weird = result
            .packages
            .iter()
            .find(|p| p.name == "WeirdVersion")
            .unwrap();
        assert_eq!(weird.version, Version::parse("1.2.3").unwrap());
    }

    #[test]
    fn test_packages_config_skips_property_ref() {
        let parser = NuGetPackagesConfigParser::new();
        let content = r#"
<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="ShouldBeSkipped" version="$(Version)" />
  <package id="Normal" version="1.2.3" />
</packages>
"#;
        let result = parser.parse(content).unwrap();
        assert_eq!(result.packages.len(), 1);
        assert_eq!(result.packages[0].name, "Normal");
        assert_eq!(result.packages[0].version, Version::parse("1.2.3").unwrap());
    }

    #[test]
    fn test_project_xml_cpm() {
        let parser = NuGetProjectXmlParser::new();
        let content = r#"
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="WithoutVersion" />
    <PackageReference Include="WithVersionOverride" VersionOverride="2.0.0" />
    <PackageReference Include="Normal" Version="1.0.0" />
  </ItemGroup>
</Project>
"#;
        let result = parser.parse(content).unwrap();
        assert_eq!(result.packages.len(), 2);

        let override_pkg = result
            .packages
            .iter()
            .find(|p| p.name == "WithVersionOverride")
            .unwrap();
        assert_eq!(override_pkg.version, Version::parse("2.0.0").unwrap());

        let normal = result.packages.iter().find(|p| p.name == "Normal").unwrap();
        assert_eq!(normal.version, Version::parse("1.0.0").unwrap());
    }

    #[test]
    fn test_project_xml_package_version() {
        let parser = NuGetProjectXmlParser::new();
        let content = r#"
<Project>
  <ItemGroup>
    <PackageVersion Include="Newtonsoft.Json" Version="13.0.1" />
  </ItemGroup>
</Project>
"#;
        let result = parser.parse(content).unwrap();
        assert_eq!(result.packages.len(), 1);
        assert_eq!(result.packages[0].name, "Newtonsoft.Json");
        assert_eq!(
            result.packages[0].version,
            Version::parse("13.0.1").unwrap()
        );
    }

    #[test]
    fn test_parser_patterns() {
        let cfg_parser = NuGetPackagesConfigParser::new();
        let proj_parser = NuGetProjectXmlParser::new();

        assert_eq!(
            cfg_parser.patterns(),
            &[FilePattern::Name("packages.config")]
        );
        assert_eq!(
            proj_parser.patterns(),
            &[
                FilePattern::Extension("csproj"),
                FilePattern::Extension("fsproj"),
                FilePattern::Extension("vbproj"),
            ]
        );
    }
}
