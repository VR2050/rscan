package com.jbzd.media.movecartoons.p396ui.novel;

import com.jbzd.media.movecartoons.p396ui.novel.NovelChapterViewActivity$bindEvent$11$1$1;
import com.jbzd.media.movecartoons.p396ui.search.model.ComicsViewModel;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import me.jessyan.progressmanager.body.ProgressInfo;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p327w.p330b.p337d.C2859c;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001f\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0005\n\u0002\u0010\u000e\n\u0002\b\u0004*\u0001\u0000\b\n\u0018\u00002\u00020\u0001J\u0019\u0010\u0005\u001a\u00020\u00042\b\u0010\u0003\u001a\u0004\u0018\u00010\u0002H\u0016¢\u0006\u0004\b\u0005\u0010\u0006J\u000f\u0010\u0007\u001a\u00020\u0004H\u0016¢\u0006\u0004\b\u0007\u0010\bJ\u000f\u0010\t\u001a\u00020\u0004H\u0016¢\u0006\u0004\b\t\u0010\bJ\u0017\u0010\f\u001a\u00020\u00042\u0006\u0010\u000b\u001a\u00020\nH\u0016¢\u0006\u0004\b\f\u0010\r¨\u0006\u000e"}, m5311d2 = {"com/jbzd/media/movecartoons/ui/novel/NovelChapterViewActivity$bindEvent$11$1$1", "Lb/w/b/d/c$c;", "Lme/jessyan/progressmanager/body/ProgressInfo;", "progress", "", "onDownloading", "(Lme/jessyan/progressmanager/body/ProgressInfo;)V", "onDownloadFailed", "()V", "onDownloadSuccess", "", "data", "onDownloadSuccessData", "(Ljava/lang/String;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class NovelChapterViewActivity$bindEvent$11$1$1 implements C2859c.c {
    public final /* synthetic */ ComicsViewModel $this_run;
    public final /* synthetic */ NovelChapterViewActivity this$0;

    public NovelChapterViewActivity$bindEvent$11$1$1(NovelChapterViewActivity novelChapterViewActivity, ComicsViewModel comicsViewModel) {
        this.this$0 = novelChapterViewActivity;
        this.$this_run = comicsViewModel;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: onDownloadSuccessData$lambda-0, reason: not valid java name */
    public static final void m5913onDownloadSuccessData$lambda0(ComicsViewModel this_run, String data) {
        Intrinsics.checkNotNullParameter(this_run, "$this_run");
        Intrinsics.checkNotNullParameter(data, "$data");
        this_run.getNovelChapterInfoBeanTxtShow().setValue(data);
    }

    @Override // p005b.p327w.p330b.p337d.C2859c.c
    public void onDownloadFailed() {
    }

    @Override // p005b.p327w.p330b.p337d.C2859c.c
    public void onDownloadSuccess() {
    }

    @Override // p005b.p327w.p330b.p337d.C2859c.c
    public void onDownloadSuccessData(@NotNull final String data) {
        Intrinsics.checkNotNullParameter(data, "data");
        NovelChapterViewActivity novelChapterViewActivity = this.this$0;
        final ComicsViewModel comicsViewModel = this.$this_run;
        novelChapterViewActivity.runOnUiThread(new Runnable() { // from class: b.a.a.a.t.j.g
            @Override // java.lang.Runnable
            public final void run() {
                NovelChapterViewActivity$bindEvent$11$1$1.m5913onDownloadSuccessData$lambda0(ComicsViewModel.this, data);
            }
        });
    }

    @Override // p005b.p327w.p330b.p337d.C2859c.c
    public void onDownloading(@Nullable ProgressInfo progress) {
        this.this$0.getLl_novel_loading().setVisibility(0);
    }
}
