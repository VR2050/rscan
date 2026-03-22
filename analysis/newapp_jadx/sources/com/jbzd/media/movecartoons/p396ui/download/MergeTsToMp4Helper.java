package com.jbzd.media.movecartoons.p396ui.download;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000$\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0002\b\u0005\bÆ\u0002\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\r\u0010\u000eJ\u001d\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u0004¢\u0006\u0004\b\u0007\u0010\bJ\u0015\u0010\u000b\u001a\u00020\n2\u0006\u0010\t\u001a\u00020\u0002¢\u0006\u0004\b\u000b\u0010\f¨\u0006\u000f"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/download/MergeTsToMp4Helper;", "", "", "json", "Ljava/io/File;", "file", "", "writeStringToFile", "(Ljava/lang/String;Ljava/io/File;)V", "taskId", "", "isMp4Exist", "(Ljava/lang/String;)Z", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class MergeTsToMp4Helper {

    @NotNull
    public static final MergeTsToMp4Helper INSTANCE = new MergeTsToMp4Helper();

    private MergeTsToMp4Helper() {
    }

    public final boolean isMp4Exist(@NotNull String taskId) {
        Intrinsics.checkNotNullParameter(taskId, "taskId");
        try {
            return new File(C2354n.m2492l0().getPath() + ((Object) File.separator) + taskId + ".mp4").exists();
        } catch (Exception e2) {
            e2.printStackTrace();
            return false;
        }
    }

    public final void writeStringToFile(@NotNull String json, @NotNull File file) {
        Intrinsics.checkNotNullParameter(json, "json");
        Intrinsics.checkNotNullParameter(file, "file");
        try {
            if (file.exists()) {
                file.delete();
                file.createNewFile();
            } else {
                file.createNewFile();
            }
            BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(file, false));
            bufferedWriter.write(json);
            bufferedWriter.close();
        } catch (Exception e2) {
            Intrinsics.stringPlus("错误:", e2);
        }
    }
}
