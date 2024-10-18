// This package contains a series of helper functions that are useful for reading APK
package apkreader

import (
	"archive/zip"
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"

	lru "github.com/elastic/go-freelru"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/util"
)

var instance *ApkReader
var once sync.Once

type fileInfo struct {
	Name   string
	Offset uint64
	Size   uint64
}

type apkInfo struct {
	Files        []fileInfo
	Device       uint64
	Inode        uint64
	LastModified int64
}

type ApkReader struct {
	apkCache *lru.SyncedLRU[util.OnDiskFileIdentifier, apkInfo]
}

func newReader(cacheSize uint32) *ApkReader {
	apkCache, err := lru.NewSynced[util.OnDiskFileIdentifier, apkInfo](cacheSize, util.OnDiskFileIdentifier.Hash32)
	if err != nil {
		log.Debugf("Could not create LRU for APK file cache: %v", err)
		return nil
	}
	return &ApkReader{apkCache: apkCache}
}

func GetReader() *ApkReader {
	once.Do(func() {
		instance = newReader(8192)
	})
	return instance
}

func (ar *ApkReader) getApkKey(inode uint64, device uint64) util.OnDiskFileIdentifier {
	return util.OnDiskFileIdentifier{
		DeviceID:    device,
		InodeNum:    inode,
		EmbedOffset: 0,
	}
}

func (ar *ApkReader) getApkInfo(path string) (*apkInfo, error) {
	statInfo, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	stat, ok := statInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, fmt.Errorf("could not cast to Stat_t")
	}
	inode := stat.Ino
	device := stat.Dev
	lastModified := statInfo.ModTime().UnixNano()
	// Fast path
	key := ar.getApkKey(inode, device)
	if v, ok := ar.apkCache.Get(key); ok {
		if v.Device == device && v.Inode == inode && lastModified == v.LastModified {
			return &v, nil
		}
	}
	// Slow path
	reader, err := zip.OpenReader(path)
	if err != nil {
		log.Debugf("Could not open APK file: %s, %v", path, err)
		return nil, err
	}
	defer reader.Close()

	apkInfo := apkInfo{
		Device:       device,
		Inode:        inode,
		LastModified: lastModified,
	}
	for _, file := range reader.File {
		if file.Method == 0 {
			f_offset, err := file.DataOffset()
			if err != nil {
				return nil, err
			}

			apkInfo.Files = append(apkInfo.Files, fileInfo{
				Name:   file.Name,
				Offset: uint64(f_offset),
				Size:   file.UncompressedSize64,
			})
		}
	}
	ar.apkCache.Add(key, apkInfo)
	return &apkInfo, nil
}

func IsApkPath(path string) bool {
	return strings.HasSuffix(path, ".apk")
}

func (ar *ApkReader) TryGetApkEmbedElfInfo(path string, offset uint64) (string, uint64, uint64) {
	if !IsApkPath(path) {
		return "", 0, 0
	}

	apkInfo, err := ar.getApkInfo(path)
	if err != nil {
		log.Debugf("Could not get APK info for %s, %v", path, err)
		return "", 0, 0
	}

	for _, file := range apkInfo.Files {
		if offset >= file.Offset && offset < file.Offset+file.Size {
			return path + "!/" + file.Name, file.Offset, file.Size
		}
	}
	return "", 0, 0
}
