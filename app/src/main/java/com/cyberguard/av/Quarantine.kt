package com.cyberguard.av

import android.content.Context
import java.io.File

/** قرنطینه: فایل مشکوک به پوشه‌ی خصوصی برنامه منتقل می‌شود (قابل بازگردانی یا حذف دائمی). */
object Quarantine {
    data class Item(val id: String, val path: String, val size: Long, val time: Long)

    private fun dir(ctx: Context): File = File(ctx.filesDir, "quarantine").also { it.mkdirs() }
    private fun indexFile(ctx: Context) = File(dir(ctx), "index.tsv")

    fun list(ctx: Context): List<Item> {
        val f = indexFile(ctx)
        if (!f.exists()) return emptyList()
        return f.readLines().mapNotNull { line ->
            val p = line.split('\t')
            if (p.size < 4) null else Item(p[0], p[1], p[2].toLongOrNull() ?: 0L, p[3].toLongOrNull() ?: 0L)
        }.filter { File(dir(ctx), it.id + ".qf").exists() }.sortedByDescending { it.time }
    }

    private fun write(ctx: Context, items: List<Item>) {
        indexFile(ctx).writeText(items.joinToString("\n") { "${it.id}\t${it.path}\t${it.size}\t${it.time}" })
    }

    fun add(ctx: Context, src: File): Boolean = try {
        val size = src.length()
        val id = System.currentTimeMillis().toString() + (src.absolutePath.hashCode() and 0x7fffffff)
        val dest = File(dir(ctx), "$id.qf")
        src.copyTo(dest, overwrite = false)
        if (!src.delete()) {
            dest.delete()
            false
        } else {
            write(ctx, list(ctx) + Item(id, src.absolutePath, size, System.currentTimeMillis()))
            true
        }
    } catch (e: Exception) { false }

    fun restore(ctx: Context, item: Item): Boolean = try {
        val q = File(dir(ctx), item.id + ".qf")
        val dest = File(item.path)
        dest.parentFile?.mkdirs()
        q.copyTo(dest, overwrite = false)
        q.delete()
        write(ctx, list(ctx).filter { it.id != item.id })
        true
    } catch (e: Exception) { false }

    fun deleteForever(ctx: Context, item: Item): Boolean = try {
        File(dir(ctx), item.id + ".qf").delete()
        write(ctx, list(ctx).filter { it.id != item.id })
        true
    } catch (e: Exception) { false }
}
