package com.jbzd.media.movecartoons.p396ui.search.view;

import android.annotation.SuppressLint;
import android.content.Context;
import android.util.AttributeSet;
import android.widget.ImageView;
import androidx.fragment.app.Fragment;
import java.util.HashMap;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00008\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\n\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\b\u0007\u0018\u00002\u00020\u0001B\u001b\u0012\b\u0010\u001b\u001a\u0004\u0018\u00010\u001a\u0012\b\u0010\u001d\u001a\u0004\u0018\u00010\u001c¢\u0006\u0004\b\u001e\u0010\u001fJ\u0015\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0005\u0010\u0006J\u0017\u0010\t\u001a\u00020\u00042\u0006\u0010\b\u001a\u00020\u0007H\u0016¢\u0006\u0004\b\t\u0010\nJ\r\u0010\u000b\u001a\u00020\u0004¢\u0006\u0004\b\u000b\u0010\fR$\u0010\r\u001a\u0004\u0018\u00010\u00028\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\r\u0010\u000e\u001a\u0004\b\u000f\u0010\u0010\"\u0004\b\u0011\u0010\u0006R>\u0010\u0014\u001a\u001e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00070\u0012j\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u0007`\u00138\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u0014\u0010\u0015\u001a\u0004\b\u0016\u0010\u0017\"\u0004\b\u0018\u0010\u0019¨\u0006 "}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/view/Bg;", "Landroid/widget/ImageView;", "Landroidx/fragment/app/Fragment;", "f", "", "addSearchBgState", "(Landroidx/fragment/app/Fragment;)V", "", "visibility", "setVisibility", "(I)V", "recoverVisibility", "()V", "presentFragment", "Landroidx/fragment/app/Fragment;", "getPresentFragment", "()Landroidx/fragment/app/Fragment;", "setPresentFragment", "Ljava/util/HashMap;", "Lkotlin/collections/HashMap;", "state", "Ljava/util/HashMap;", "getState", "()Ljava/util/HashMap;", "setState", "(Ljava/util/HashMap;)V", "Landroid/content/Context;", "context", "Landroid/util/AttributeSet;", "attrs", "<init>", "(Landroid/content/Context;Landroid/util/AttributeSet;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
@SuppressLint({"AppCompatCustomView"})
/* renamed from: com.jbzd.media.movecartoons.ui.search.view.Bg */
/* loaded from: classes2.dex */
public final class C3878Bg extends ImageView {

    @Nullable
    private Fragment presentFragment;

    @NotNull
    private HashMap<Fragment, Integer> state;

    public C3878Bg(@Nullable Context context, @Nullable AttributeSet attributeSet) {
        super(context, attributeSet);
        this.state = new HashMap<>();
    }

    public void _$_clearFindViewByIdCache() {
    }

    public final void addSearchBgState(@NotNull Fragment f2) {
        Intrinsics.checkNotNullParameter(f2, "f");
        this.state.put(f2, 0);
    }

    @Nullable
    public final Fragment getPresentFragment() {
        return this.presentFragment;
    }

    @NotNull
    public final HashMap<Fragment, Integer> getState() {
        return this.state;
    }

    public final void recoverVisibility() {
        if (this.state.containsKey(this.presentFragment)) {
            Integer num = this.state.get(this.presentFragment);
            Intrinsics.checkNotNull(num);
            setVisibility(num.intValue());
        }
    }

    public final void setPresentFragment(@Nullable Fragment fragment) {
        this.presentFragment = fragment;
    }

    public final void setState(@NotNull HashMap<Fragment, Integer> hashMap) {
        Intrinsics.checkNotNullParameter(hashMap, "<set-?>");
        this.state = hashMap;
    }

    @Override // android.widget.ImageView, android.view.View
    public void setVisibility(int visibility) {
        super.setVisibility(visibility);
        Fragment fragment = this.presentFragment;
        if (fragment != null) {
            HashMap<Fragment, Integer> hashMap = this.state;
            Intrinsics.checkNotNull(fragment);
            hashMap.put(fragment, Integer.valueOf(visibility));
        }
    }
}
