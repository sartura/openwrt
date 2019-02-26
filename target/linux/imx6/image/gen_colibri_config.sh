#!/bin/sh

# Generate image.json which is used by Toradex Easy Installer

IMAGE_NAME=$1

cat << EOF
{
  "config_format": 1,
  "name": "Toradex OpenWrt image",
  "description": "OpenWrt firmware for Toradex Easy Installer",
  "version": "0.1",
  "release_date": "$(date -I)",
  "prepare_script": "prepare.sh",
  "wrapup_script": "wrapup.sh",
  "supported_product_ids": [
    "0014",
    "0015",
    "0016",
    "0017"
  ],
  "blockdevs": [
    {
      "partitions": [
        {
          "content": {
            "label": "BOOT",
            "mkfs_options": "",
            "uncompressed_size": 4.87109375,
            "filesystem_type": "FAT",
            "filename": "${IMAGE_NAME}.bootfs.tar.xz"
          },
          "partition_size_nominal": 16,
          "want_maximised": false
        },
        {
          "content": {
            "label": "RFS",
            "mkfs_options": "-E nodiscard",
            "uncompressed_size": 396.27734375,
            "filesystem_type": "ext4",
            "filename": "${IMAGE_NAME}.rootfs.tar.xz"
          },
          "partition_size_nominal": 512,
          "want_maximised": true
        }
      ],
      "name": "mmcblk0"
    },
    {
      "content": {
        "rawfiles": [
          {
            "filename": "SPL",
            "dd_options": "seek=2"
          },
          {
            "filename": "u-boot.img",
            "dd_options": "seek=138"
          }
        ],
        "filesystem_type": "raw"
      },
      "name": "mmcblk0boot0"
    }
  ]
}
EOF
