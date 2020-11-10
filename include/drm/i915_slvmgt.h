/* Copyright Cyberus Technology GmbH *
 *        All rights reserved        */

/* SPDX-License-Identifier: GPL-2.0  */

#ifndef _I915_SLVMGT_H_
#define _I915_SLVMGT_H_

#include <drm/drm_edid.h>

/*
 * DATA TYPES
 */

struct eventfd_ctx;
struct intel_vgpu;
struct vfio_device_gfx_plane_info;
struct slvmgt_ops;

struct slvmgt_vgpu {
	const struct slvmgt_ops *slvm;
	struct intel_vgpu *vgpu;

	spinlock_t eventfd_lock;
	struct eventfd_ctx *eventfd_ctx;
};

/*
 * Callbacks into the SLVM module. These are a subset of struct intel_gvt_mpt
 * and are necessary, because SLVMGT cannot directly interact with the memory
 * map of a VM.
 */
struct slvmgt_ops {
	int (*page_track_set)(struct slvmgt_vgpu *vgpu, u64 gfn, bool on);
	int (*access_gpa)(struct slvmgt_vgpu *vgpu, unsigned long gpa,
			  void *buf, unsigned long len, bool is_write);
	int (*gfn_to_pfn)(struct slvmgt_vgpu *vgpu, u64 gfn,
			  unsigned long *pfn);
	bool (*is_valid_gfn)(struct slvmgt_vgpu *vgpu, u64 gfn);
	int (*map_gfn_to_mfn)(struct slvmgt_vgpu *vgpu, u64 gfn, u64 mfn,
			      unsigned int nr, bool map);

	int (*dma_map_guest_page)(struct slvmgt_vgpu *vgpu, u64 gfn,
				  unsigned long size, dma_addr_t *dma_addr);
	int (*dma_unmap_guest_page)(struct slvmgt_vgpu *vgpu,
				    dma_addr_t dma_addr);
	int (*dma_pin_guest_page)(struct slvmgt_vgpu *vgpu,
				  dma_addr_t dma_addr);
};

/* vGPU types for slvmgt_vgpu_create */
enum slvmgt_vgpu_type {
	SLVMGT_VGPU_TYPE_64M,
	SLVMGT_VGPU_TYPE_128M,
};

/* Display geometry information */
struct slvmgt_edid {
	char data[EDID_LENGTH];
};

/* Memory space types for slvmgt_vgpu_forward_access */
enum slvmgt_space {
	SLVMGT_SPACE_MMIO,
	SLVMGT_SPACE_PCI_CONFIG,
	SLVMGT_SPACE_TRACKED_MEM,
};

/*
 * API for main SLVM module
 */
int slvmgt_vgpu_create(struct slvmgt_vgpu *vgpu, const struct slvmgt_ops *ops,
		       const struct slvmgt_edid *edid,
		       enum slvmgt_vgpu_type vgpu_type);
void slvmgt_vgpu_destroy(struct slvmgt_vgpu *vgpu);
int slvmgt_vgpu_set_edid(struct slvmgt_vgpu *vgpu,
			 const struct slvmgt_edid *edid);
int slvmgt_vgpu_set_irqfd(struct slvmgt_vgpu *vgpu, struct eventfd_ctx *ctx);
int slvmgt_vgpu_forward_access(struct slvmgt_vgpu *vgpu,
			       enum slvmgt_space space, void *data,
			       unsigned long offset, unsigned long size,
			       bool is_write);
int slvmgt_vgpu_query_plane(struct slvmgt_vgpu *vgpu,
			    struct vfio_device_gfx_plane_info *plane);
int slvmgt_vgpu_get_dmabuf(struct slvmgt_vgpu *vgpu, unsigned int dmabuf_id);
void slvmgt_vgpu_display_hotplug(struct slvmgt_vgpu *vgpu, bool connected);
void slvmgt_vgpu_reset(struct slvmgt_vgpu *vgpu);

#endif
