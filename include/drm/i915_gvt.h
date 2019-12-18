/*
 * Copyright(c) 2011-2016 Intel Corporation. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef _I915_GVT_H_
#define _I915_GVT_H_

#include <drm/i915_gvt_hypercall.h>

struct attribute;
struct attribute_group;

struct intel_vgpu;
struct intel_gvt;
struct intel_vgpu_type;
struct intel_vgpu_port;

/* reg.h */
#define INTEL_GVT_OPREGION_PAGES	2
#define INTEL_GVT_OPREGION_SIZE		(INTEL_GVT_OPREGION_PAGES * PAGE_SIZE)

/* gtt.h */
#define INTEL_GVT_INVALID_ADDR (~0UL)

/* edid.h  */
#define EDID_SIZE		128
#define EDID_ADDR		0x50 /* Linux hvm EDID addr */

/* display.h */
enum intel_vgpu_edid {
	GVT_EDID_1024_768,
	GVT_EDID_1920_1200,
	GVT_EDID_NUM,
};

struct intel_gvt_ops {
	int (*emulate_cfg_read)(struct intel_vgpu *, unsigned int, void *,
				unsigned int);
	int (*emulate_cfg_write)(struct intel_vgpu *, unsigned int, void *,
				unsigned int);
	int (*emulate_mmio_read)(struct intel_vgpu *, u64, void *,
				unsigned int);
	int (*emulate_mmio_write)(struct intel_vgpu *, u64, void *,
				unsigned int);
	struct intel_vgpu *(*vgpu_create)(struct intel_gvt *,
				struct intel_vgpu_type *);
	void (*vgpu_destroy)(struct intel_vgpu *vgpu);
	void (*vgpu_release)(struct intel_vgpu *vgpu);
	void (*vgpu_reset)(struct intel_vgpu *);
	void (*vgpu_activate)(struct intel_vgpu *);
	void (*vgpu_deactivate)(struct intel_vgpu *);
	struct intel_vgpu_type *(*gvt_find_vgpu_type)(struct intel_gvt *gvt,
			const char *name);
	bool (*get_gvt_attrs)(struct attribute ***type_attrs,
			struct attribute_group ***intel_vgpu_type_groups);
	int (*vgpu_query_plane)(struct intel_vgpu *vgpu, void *);
	int (*vgpu_get_dmabuf)(struct intel_vgpu *vgpu, unsigned int);
	int (*write_protect_handler)(struct intel_vgpu *, u64, void *,
				     unsigned int);
	void (*emulate_hotplug)(struct intel_vgpu *vgpu, bool connected);
};

bool intel_vgpu_active_find(struct intel_vgpu *vgpu, bool (*pred)(struct intel_vgpu *, void *), void *ctx);

struct intel_gvt *intel_gvt_from_kdev(struct device *kobj);
void *intel_vgpu_vdev(struct intel_vgpu *vgpu);
void intel_vgpu_set_vdev(struct intel_vgpu *vgpu, void *vdev);
int intel_vgpu_id(struct intel_vgpu *vgpu);
unsigned intel_vgpu_hw_id(struct intel_vgpu *vgpu);

struct device *intel_vgpu_pdev(struct intel_vgpu *vgpu);
void *intel_vgpu_opregion_va(struct intel_vgpu *vgpu);
struct intel_vgpu_port *intel_vgpu_port(struct intel_vgpu *vgpu, size_t port);

unsigned int vgpu_edid_xres(struct intel_vgpu_port *port);
unsigned int vgpu_edid_yres(struct intel_vgpu_port *port);
void *intel_vgpu_edid_block(struct intel_vgpu_port *port);

void intel_vgpu_set_handle(struct intel_vgpu *vgpu, unsigned long handle);
unsigned long intel_vgpu_handle(struct intel_vgpu *vgpu);

u32 *intel_vgpu_bar_ptr(struct intel_vgpu *vgpu, int bar);
u64 intel_vgpu_get_bar_gpa(struct intel_vgpu *vgpu, int bar);
u64 intel_vgpu_get_bar_size(struct intel_vgpu *vgpu, int bar);

u64 intel_gvt_cfg_space_size(struct intel_vgpu *vgpu);

u64 intel_gvt_aperture_pa_base(struct intel_vgpu *vgpu);
u64 intel_vgpu_aperture_offset(struct intel_vgpu *vgpu);
u64 intel_vgpu_aperture_size(struct intel_vgpu *vgpu);
u64 intel_gvt_aperture_size(struct intel_vgpu *vgpu);

struct io_mapping *intel_gvt_gtt_iomap(struct intel_vgpu *vgpu);
bool intel_gvt_in_gtt(struct intel_vgpu *vgpu, u64 off);

struct dentry *intel_vgpu_debugfs(struct intel_vgpu *vgpu);

#endif /* _I915_GVT_H_ */
