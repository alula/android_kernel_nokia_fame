#ifndef __QCOM_MDT_LOADER_H__
#define __QCOM_MDT_LOADER_H__

struct resource_table *qcom_mdt_find_rsc_table(struct rproc *rproc, const struct firmware *fw, int *tablesz);
int qcom_mdt_load(struct rproc *rproc, unsigned int pas_id, const struct firmware *fw, phys_addr_t mem_phys, void *mem_region, size_t mem_size);

#endif
