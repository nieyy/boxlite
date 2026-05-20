#ifndef BOXLITE_INTERNAL_H
#define BOXLITE_INTERNAL_H

// Internal BoxLite C API — not part of the public SDK surface.
//
// This header exposes implementation details that are only intended for use by
// first-party consumers (e.g. boxlite-runner). External SDK users should only
// include boxlite.h.

#include "boxlite.h"

// Returns the path to the gvproxy HTTP admin Unix socket for this box.
//
// The path follows the layout: `<home_dir>/boxes/<box_id>/sockets/gvproxy-admin.sock`
//
// The caller must free the returned string with `boxlite_free_string`.
// Returns NULL if handle is NULL or home_dir is not set (e.g. REST runtime).
char *boxlite_box_admin_sock_path(CBoxHandle *handle);

#endif // BOXLITE_INTERNAL_H
