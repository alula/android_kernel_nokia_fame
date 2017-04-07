/*
 * Qualcomm Peripheral Image Loader
 *
 * Copyright (C) 2016 Linaro Ltd
 * Copyright (C) 2015 Sony Mobile Communications Inc
 * Copyright (c) 2012-2013, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/elf.h>
#include <linux/firmware.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/qcom_scm.h>
#include <linux/remoteproc.h>
#include <linux/slab.h>

#include "remoteproc_internal.h"

#define QCOM_MDT_TYPE_MASK	(7 << 24)
#define QCOM_MDT_TYPE_HASH	(2 << 24)
#define QCOM_MDT_RELOCATABLE	BIT(27)

/**
 * qcom_mdt_find_rsc_table() - provide dummy resource table for remoteproc
 * @rproc:	remoteproc handle
 * @fw:		firmware header
 * @tablesz:	outgoing size of the table
 *
 * Returns a dummy table.
 */
struct resource_table *qcom_mdt_find_rsc_table(struct rproc *rproc,
					       const struct firmware *fw,
					       int *tablesz)
{
	static struct resource_table table = { .ver = 1, };

	*tablesz = sizeof(table);
	return &table;
}
EXPORT_SYMBOL_GPL(qcom_mdt_find_rsc_table);

/**
 * qcom_mdt_load() - load the firmware which header is defined in fw
 * @rproc:	rproc handle
 * @pas_id:	PAS identifier to load this firmware into
 * @fw:		frimware object for the header
 * @mem_phys:	physical address of reserved memory region for the firmware
 * @mem_region:	pointer to a mapping of the reserved memory region
 * @mem_size:	size of the reserved memory region
 *
 * Returns 0 on success, negative errno otherwise.
 */
int qcom_mdt_load(struct rproc *rproc,
		  unsigned int pas_id,
		  const struct firmware *fw,
		  phys_addr_t mem_phys,
		  void *mem_region,
		  size_t mem_size)
{
	const struct elf32_phdr *phdrs;
	const struct elf32_phdr *phdr;
	const struct elf32_hdr *ehdr;
	unsigned int fw_name_len;
	phys_addr_t min_addr = (phys_addr_t)ULLONG_MAX;
	phys_addr_t max_addr = 0;
	bool relocate = false;
	char *fw_name;
	void *ptr;
	int ret;
	int i;

	ehdr = (struct elf32_hdr *)fw->data;
	phdrs = (struct elf32_phdr *)(ehdr + 1);

	for (i = 0; i < ehdr->e_phnum; i++) {
		phdr = &phdrs[i];

		if (phdr->p_type != PT_LOAD)
			continue;

		if ((phdr->p_flags & QCOM_MDT_TYPE_MASK) == QCOM_MDT_TYPE_HASH)
			continue;

		if (!phdr->p_memsz)
			continue;

		if (phdr->p_flags & QCOM_MDT_RELOCATABLE)
			relocate = true;

		if (phdr->p_paddr < min_addr)
			min_addr = phdr->p_paddr;

		if (phdr->p_paddr + phdr->p_memsz > max_addr)
			max_addr = round_up(phdr->p_paddr + phdr->p_memsz, SZ_4K);
	}

	ret = qcom_scm_pas_init_image(pas_id, fw->data, fw->size);
	if (ret) {
		dev_err(&rproc->dev, "invalid firmware metadata\n");
		return -EINVAL;
	}

	if (relocate) {
		ret = qcom_scm_pas_mem_setup(pas_id, mem_phys, max_addr - min_addr);
		if (ret) {
			dev_err(&rproc->dev, "unable to setup memory for image\n");
			return -EINVAL;
		}
	}

	fw_name_len = strlen(rproc->firmware);
	if (fw_name_len <= 4)
		return -EINVAL;

	fw_name = kstrdup(rproc->firmware, GFP_KERNEL);
	if (!fw_name)
		return -ENOMEM;

	for (i = 0; i < ehdr->e_phnum; i++) {
		phdr = &phdrs[i];

		if (phdr->p_type != PT_LOAD)
			continue;

		if ((phdr->p_flags & QCOM_MDT_TYPE_MASK) == QCOM_MDT_TYPE_HASH)
			continue;

		if (!phdr->p_memsz)
			continue;

		if (phdr->p_flags & QCOM_MDT_RELOCATABLE)
			ptr = mem_region + phdr->p_paddr - min_addr;
		else
			ptr = mem_region + phdr->p_paddr - mem_phys;

		if (ptr < mem_region || ptr + phdr->p_memsz > mem_region + mem_size) {
			dev_err(&rproc->dev, "segment outside memory range\n");
			ret = -EINVAL;
			break;
		}

		if (phdr->p_filesz) {
			sprintf(fw_name + fw_name_len - 3, "b%02d", i);
			ret = request_firmware(&fw, fw_name, &rproc->dev);
			if (ret) {
				dev_err(&rproc->dev, "failed to load %s\n", fw_name);
				break;
			}

			memcpy(ptr, fw->data, fw->size);

			release_firmware(fw);
		}

		if (phdr->p_memsz > phdr->p_filesz)
			memset(ptr + phdr->p_filesz, 0, phdr->p_memsz - phdr->p_filesz);
	}

	kfree(fw_name);

	return ret;
}
EXPORT_SYMBOL_GPL(qcom_mdt_load);
