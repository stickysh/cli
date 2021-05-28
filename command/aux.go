package command

import (
	"archive/zip"
	"bytes"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"sigs.k8s.io/yaml"
)

func loadDefFile(path string) ([]byte, error) {
	rawDef, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	buf, err := ioutil.ReadAll(rawDef)
	jsonDef, err := yaml.YAMLToJSON(buf)
	if err != nil {
		return nil, err
	}

	return jsonDef, nil
}

func zipFolder(root string) (io.Reader, error) {
	buf := new(bytes.Buffer)

	w := zip.NewWriter(buf)
	defer w.Close()

	walker := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		zipPath := path
		if filepath.IsAbs(root) {
			zipPath, err = filepath.Rel(root, path)
			if err != nil {
				return err
			}
		}

		f, err := w.Create(zipPath)
		if err != nil {
			return err
		}

		_, err = io.Copy(f, file)
		if err != nil {
			return err
		}

		return nil
	}

	err := filepath.Walk(root, walker)
	if err != nil {
		return nil, err
	}

	return buf, nil
}
