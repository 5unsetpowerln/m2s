use std::{
    collections::BTreeMap,
    fs,
    io::{BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
    process::exit,
};

use anyhow::{bail, Context, Result};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long)]
    input: PathBuf,

    #[arg(long)]
    output: PathBuf,

    #[arg(long)]
    template: Option<PathBuf>,

    #[arg(long)]
    theme: Option<PathBuf>,
}

struct Page {
    title: String,
    path: PathBuf,
    out: Option<String>,
    template: Option<PathBuf>,
}

impl Page {
    fn new(title: &str, path: &Path, template: Option<&PathBuf>) -> Self {
        Self {
            title: title.to_string(),
            path: path.to_path_buf(),
            out: None,
            template: template.map(|t| t.to_path_buf()),
        }
    }

    fn render(&mut self, plugins: &comrak::Plugins) -> Result<()> {
        let mut reader = BufReader::new(fs::File::open(&self.path).unwrap());
        let mut contents = String::new();
        reader.read_to_string(&mut contents).unwrap();

        let html =
            comrak::markdown_to_html_with_plugins(&contents, &comrak::Options::default(), plugins);
        let html_escaped = html.replace('{', "&#123;").replace('}', "&#125;");

        match self.template {
            Some(ref template_path) => {
                // let out =
                let template_file = fs::File::open(template_path)
                    .with_context(|| format!("failed to open {}", template_path.display()))?;
                let mut reader = BufReader::new(template_file);
                let mut template = String::new();
                reader.read_to_string(&mut template).with_context(|| {
                    format!("failed to read contents from {}", template_path.display())
                })?;
                self.out = Some(template.replace("CONTENTS", &html_escaped));
                Ok(())
            }
            None => {
                self.out = Some(html_escaped);
                Ok(())
            }
        }
    }

    fn write(&mut self, root_dir: &Path) -> Result<()> {
        let binding = self.path.file_name().unwrap().to_string_lossy().to_string();
        let name = binding.strip_suffix(".md").unwrap();

        let out_dir_path = root_dir.join(name);
        let out_path = out_dir_path.join("+page.svelte");

        if self.out.is_none() {
            bail!("page isn't rendered yet!")
        }

        let out = self.out.clone().unwrap();

        fs::create_dir_all(&out_dir_path)
            .with_context(|| format!("failed to create {}", out_dir_path.display()))?;
        let out_file = fs::File::create(&out_path)
            .with_context(|| format!("failed to create {}", out_path.display()))?;
        let mut writer = BufWriter::new(out_file);

        writer
            .write_all(out.as_bytes())
            .with_context(|| format!("failed to write contents to {}", out_path.display()))?;

        Ok(())
    }
}

fn md_list(input_dir_path: &PathBuf) -> Vec<PathBuf> {
    let input_dir = fs::read_dir(input_dir_path).unwrap();
    let mut md_list = vec![];
    for file in input_dir {
        let file = file.unwrap();
        let file_name = file.file_name().to_string_lossy().to_string();
        let file_type = file.file_type().unwrap();
        if !(file_name.ends_with(".md") && file_type.is_file()) {
            continue;
        }

        let file_path = file.path();
        md_list.push(file_path);
    }
    md_list
}

fn gen_syntax_adapter(
    theme_path: Option<&PathBuf>,
) -> Result<comrak::plugins::syntect::SyntectAdapter> {
    let path = theme_path.map(|t| t.to_path_buf());

    let mut plugins = comrak::Plugins::default();

    Ok(match path {
        Some(t) => {
            let mut reader = BufReader::new(fs::File::open(t).unwrap());
            let theme = syntect::highlighting::ThemeSet::load_from_reader(&mut reader).unwrap();
            let mut themes = BTreeMap::new();
            themes.insert("custom".to_string(), theme);
            let mut theme_set = syntect::highlighting::ThemeSet::new();
            theme_set.themes = themes;

            comrak::plugins::syntect::SyntectAdapterBuilder::default()
                .theme_set(theme_set)
                .theme("custom")
                .build()
        }
        None => comrak::plugins::syntect::SyntectAdapter::new(None),
    })
}

fn main() {
    let args = Args::parse();
    let input_dir_path = args.input;
    let output_dir_path = args.output;
    let template = args.template.as_ref();
    let theme = args.theme;

    let adapter = match gen_syntax_adapter(theme.as_ref()) {
        Ok(p) => p,
        Err(e) => {
            println!("failed to generate render plugins: {}", e);
            exit(-1);
        }
    };
    let mut plugins = comrak::Plugins::default();
    plugins.render.codefence_syntax_highlighter = Some(&adapter);

    let mut pages = vec![];

    md_list(&input_dir_path).iter().for_each(|md| {
        let name = md.file_name().unwrap().to_string_lossy().to_string();
        let mut page = Page::new(name.strip_suffix(".md").unwrap(), md, template);
        page.render(&plugins).unwrap();
        pages.push(page);
    });

    pages.iter_mut().for_each(|page| {
        if let Err(e) = page.write(&output_dir_path) {
            println!("{}", e);
        }
    })
}

mod test {
    use std::io;
    #[allow(unused)]
    use std::{fs, path::PathBuf, str::FromStr};

    #[test]
    fn md_list() {
        match fs::remove_dir_all("./test_files") {
            Ok(_) => (),
            Err(e) => {
                if e.kind() != io::ErrorKind::NotFound {
                    panic!("{}", e)
                }
            }
        };
        fs::create_dir_all("./test_files/input").unwrap();
        fs::create_dir_all("./test_files/output").unwrap();

        let input_files = ["a.md", "b.md", "投稿.md"];
        let dummy_files = ["マークダウンじゃない", "dummy"];
        let dummy_dirs = ["dir", "ディレクトリ"];

        input_files.iter().for_each(|name| {
            let path = format!("./test_files/input/{}", name);
            fs::File::create(path).unwrap();
        });
        dummy_files.iter().for_each(|name| {
            let path = format!("./test_files/input/{}", name);
            fs::File::create(path).unwrap();
        });
        dummy_dirs.iter().for_each(|name| {
            let path = format!("./test_files/input/{}", name);
            fs::create_dir(path).unwrap();
        });

        let input_dir = PathBuf::from_str("./test_files/input").unwrap();
        let md_list = super::md_list(&input_dir);

        for input_file in input_files {
            let path = PathBuf::from_str(&format!("./test_files/input/{}", input_file)).unwrap();
            assert!(md_list.contains(&path));
        }

        for dummy_file in dummy_files {
            let path = PathBuf::from_str(&format!("./test_files/input/{}", dummy_file)).unwrap();
            assert!(!md_list.contains(&path));
        }

        for dummy_dir in dummy_dirs {
            let path = PathBuf::from_str(&format!("./test_files/input/{}", dummy_dir)).unwrap();
            assert!(!md_list.contains(&path));
        }

        fs::remove_dir_all("./test_files").unwrap();
    }
}
