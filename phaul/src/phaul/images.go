package phaul

import (
	"fmt"
	"os"
	"path/filepath"
)

type images struct {
	cursor int
	sfx    string
}

const images_dir = "phaul_img"

func preparePhaulImages(typ string) (*images, error) {
	err := os.Mkdir(images_dir+"_"+typ, 0700)
	if err != nil {
		return nil, err
	}

	return &images{sfx: typ}, nil
}

func (i *images) getPath(idx int) string {
	return fmt.Sprintf(images_dir+"_"+i.sfx+"/%d", idx)
}

func (i *images) openNextDir() (*os.File, error) {
	ipath := i.getPath(i.cursor)
	err := os.Mkdir(ipath, 0700)
	if err != nil {
		return nil, err
	}

	i.cursor++
	return os.Open(ipath)
}

func (i *images) lastImagesDir() string {
	var ret string
	if i.cursor == 0 {
		ret = ""
	} else {
		ret, _ = filepath.Abs(i.getPath(i.cursor - 1))
	}
	return ret
}
