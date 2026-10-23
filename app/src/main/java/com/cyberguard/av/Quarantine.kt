package com.cyberguard.av

import android.content.Context
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption

/**
 * Quarantine stores moved files in app-private storage. It never overwrites an
 * existing destination when restoring. The index is best-effort; missing payloads
 * are filtered from the visible list.
 */
object Quarantine {
    data class Item(val id: String, val path: String, val size: Long, val time: Long)

    private fun dir(ctx: Context): File =
        File(ctx.filesDir, "quarantine").also { it.mkdirs() }

    private fun indexFile(ctx: Context) = File(dir(ctx), "index.tsv")
    private fun payload(ctx: Context, id: String): File? =
        if (id.matches(Regex("[0-9]{1,30}"))) File(dir(ctx), "$id.qf") else null

    fun list(ctx: Context): List<Item> {
        val f = indexFile(ctx)
        if (!f.exists()) return emptyList()
        return try {
            f.readLines().mapNotNull { line ->
                val p = line.split('\t')
                if (p.size < 4 || !p[0].matches(Regex("[0-9]{1,30}"))) null
                else Item(p[0], p[1], p[2].toLongOrNull() ?: return@mapNotNull null,
                    p[3].toLongOrNull() ?: return@mapNotNull null)
            }.filter { payload(ctx, it.id)?.isFile == true }
                .sortedByDescending { it.time }
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun write(ctx: Context, items: List<Item>): Boolean = try {
        val index = indexFile(ctx)
        val temp = File(dir(ctx), "index.tmp")
        temp.writeText(items.joinToString("\n") {
            "${it.id}\t${it.path.replace("\t", "").replace("\n", "")}\t${it.size}\t${it.time}"
        })
        try {
            Files.move(temp.toPath(), index.toPath(),
                StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        } catch (_: Exception) {
            Files.move(temp.toPath(), index.toPath(), StandardCopyOption.REPLACE_EXISTING)
        }
        true
    } catch (_: Exception) {
        false
    }

    fun add(ctx: Context, src: File): Boolean {
        if (!src.isFile || !src.canRead()) return false
        val canonical = try { src.canonicalFile } catch (_: Exception) { return false }
        val id = System.currentTimeMillis().toString() + (canonical.path.hashCode().toLong() and 0x7fffffffL).toString()
        val dest = payload(ctx, id) ?: return false
        if (dest.exists()) return false

        return try {
            val originalSize = canonical.length()
            val originalHash = Scanner.sha256(canonical)
            canonical.copyTo(dest, overwrite = false)

            // Do not remove the source unless the copied payload verifies.
            if (!dest.isFile || dest.length() != originalSize ||
                Scanner.sha256(dest) != originalHash
            ) {
                dest.delete()
                return false
            }

            if (!canonical.delete()) {
                dest.delete()
                return false
            }

            val updated = list(ctx) + Item(id, canonical.absolutePath, originalSize, System.currentTimeMillis())
            if (!write(ctx, updated)) {
                // Best-effort rollback if the index cannot be updated.
                try {
                    dest.copyTo(canonical, overwrite = false)
                    if (canonical.length() == originalSize && Scanner.sha256(canonical) == originalHash) {
                        dest.delete()
                    }
                } catch (_: Exception) { }
                return false
            }
            true
        } catch (_: Exception) {
            dest.delete()
            false
        }
    }

    fun restore(ctx: Context, item: Item): Boolean {
        val q = payload(ctx, item.id) ?: return false
        if (!q.isFile || q.length() != item.size) return false
        val dest = try { File(item.path).canonicalFile } catch (_: Exception) { return false }
        if (dest.exists()) return false

        return try {
            dest.parentFile?.mkdirs()
            q.copyTo(dest, overwrite = false)
            if (!dest.isFile || dest.length() != item.size) {
                dest.delete()
                return false
            }
            if (!q.delete()) {
                dest.delete()
                return false
            }
            write(ctx, list(ctx).filterNot { it.id == item.id })
            true
        } catch (_: Exception) {
            false
        }
    }

    fun deleteForever(ctx: Context, item: Item): Boolean {
        val q = payload(ctx, item.id) ?: return false
        if (!q.exists()) {
            write(ctx, list(ctx).filterNot { it.id == item.id })
            return true
        }
        if (!q.isFile || !q.delete()) return false
        write(ctx, list(ctx).filterNot { it.id == item.id })
        return !q.exists()
    }
}
