package com.chad.library.adapter.base.viewholder;

import android.util.SparseArray;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.annotation.ColorInt;
import androidx.annotation.ColorRes;
import androidx.annotation.DrawableRes;
import androidx.annotation.IdRes;
import androidx.exifinterface.media.ExifInterface;
import androidx.recyclerview.widget.RecyclerView;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p143g.p144a.p146l.C1568e;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00008\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0005\n\u0002\u0010\r\n\u0002\b\u0012\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0006\b\u0016\u0018\u00002\u00020\u0001B\u000f\u0012\u0006\u0010'\u001a\u00020\u0002¢\u0006\u0004\b(\u0010)J#\u0010\u0007\u001a\u00020\u0006\"\b\b\u0000\u0010\u0003*\u00020\u00022\b\b\u0001\u0010\u0005\u001a\u00020\u0004H\u0016¢\u0006\u0004\b\u0007\u0010\bJ#\u0010\t\u001a\u00028\u0000\"\b\b\u0000\u0010\u0003*\u00020\u00022\b\b\u0001\u0010\u0005\u001a\u00020\u0004H\u0016¢\u0006\u0004\b\t\u0010\nJ#\u0010\u000b\u001a\u0004\u0018\u00018\u0000\"\b\b\u0000\u0010\u0003*\u00020\u00022\b\b\u0001\u0010\u0005\u001a\u00020\u0004¢\u0006\u0004\b\u000b\u0010\nJ#\u0010\u000e\u001a\u00020\u00002\b\b\u0001\u0010\u0005\u001a\u00020\u00042\b\u0010\r\u001a\u0004\u0018\u00010\fH\u0016¢\u0006\u0004\b\u000e\u0010\u000fJ#\u0010\u0011\u001a\u00020\u00002\b\b\u0001\u0010\u0005\u001a\u00020\u00042\b\b\u0001\u0010\u0010\u001a\u00020\u0004H\u0016¢\u0006\u0004\b\u0011\u0010\u0012J#\u0010\u0014\u001a\u00020\u00002\b\b\u0001\u0010\u0005\u001a\u00020\u00042\b\b\u0001\u0010\u0013\u001a\u00020\u0004H\u0016¢\u0006\u0004\b\u0014\u0010\u0012J#\u0010\u0016\u001a\u00020\u00002\b\b\u0001\u0010\u0005\u001a\u00020\u00042\b\b\u0001\u0010\u0015\u001a\u00020\u0004H\u0016¢\u0006\u0004\b\u0016\u0010\u0012J#\u0010\u0018\u001a\u00020\u00002\b\b\u0001\u0010\u0005\u001a\u00020\u00042\b\b\u0001\u0010\u0017\u001a\u00020\u0004H\u0016¢\u0006\u0004\b\u0018\u0010\u0012J!\u0010\u001a\u001a\u00020\u00002\b\b\u0001\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0019\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u001a\u0010\u001bJ!\u0010\u001d\u001a\u00020\u00002\b\b\u0001\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u001c\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u001d\u0010\u001bJ!\u0010\u001e\u001a\u00020\u00002\b\b\u0001\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u001c\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u001e\u0010\u001bJ)\u0010\"\u001a\u00020\u00002\b\b\u0001\u0010\u0005\u001a\u00020\u00042\u000e\b\u0002\u0010!\u001a\b\u0012\u0004\u0012\u00020 0\u001fH\u0016¢\u0006\u0004\b\"\u0010#R\u001c\u0010&\u001a\b\u0012\u0004\u0012\u00020\u00020$8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b\t\u0010%¨\u0006*"}, m5311d2 = {"Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "Landroidx/recyclerview/widget/RecyclerView$ViewHolder;", "Landroid/view/View;", ExifInterface.GPS_DIRECTION_TRUE, "", "viewId", "", "d", "(I)Z", "b", "(I)Landroid/view/View;", "c", "", "value", "i", "(ILjava/lang/CharSequence;)Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "color", "j", "(II)Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "colorRes", "k", "imageResId", "g", "backgroundRes", C1568e.f1949a, "isVisible", "l", "(IZ)Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "isGone", "f", "a", "Lkotlin/Function0;", "", "onClick", "h", "(ILkotlin/jvm/functions/Function0;)Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "Landroid/util/SparseArray;", "Landroid/util/SparseArray;", "views", "view", "<init>", "(Landroid/view/View;)V", "com.github.CymChad.brvah"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes.dex */
public class BaseViewHolder extends RecyclerView.ViewHolder {

    /* renamed from: a */
    public static final /* synthetic */ int f8893a = 0;

    /* renamed from: b, reason: from kotlin metadata */
    @NotNull
    public final SparseArray<View> views;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public BaseViewHolder(@NotNull View view) {
        super(view);
        Intrinsics.checkNotNullParameter(view, "view");
        this.itemView.setTag(this);
        this.views = new SparseArray<>();
    }

    @NotNull
    /* renamed from: a */
    public BaseViewHolder m3911a(@IdRes int viewId, boolean isGone) {
        m3912b(viewId).setVisibility(isGone ? 4 : 0);
        return this;
    }

    @NotNull
    /* renamed from: b */
    public <T extends View> T m3912b(@IdRes int viewId) {
        T t = (T) m3913c(viewId);
        if (t != null) {
            return t;
        }
        throw new IllegalStateException(Intrinsics.stringPlus("No view found with id ", Integer.valueOf(viewId)).toString());
    }

    @Nullable
    /* renamed from: c */
    public final <T extends View> T m3913c(@IdRes int viewId) {
        T t;
        T t2 = (T) this.views.get(viewId);
        if (t2 == null && (t = (T) this.itemView.findViewById(viewId)) != null) {
            this.views.put(viewId, t);
            return t;
        }
        if (t2 != null) {
            return t2;
        }
        return null;
    }

    /* renamed from: d */
    public <T extends View> boolean m3914d(@IdRes int viewId) {
        return m3913c(viewId) != null;
    }

    @NotNull
    /* renamed from: e */
    public BaseViewHolder m3915e(@IdRes int viewId, @DrawableRes int backgroundRes) {
        m3912b(viewId).setBackgroundResource(backgroundRes);
        return this;
    }

    @NotNull
    /* renamed from: f */
    public BaseViewHolder m3916f(@IdRes int viewId, boolean isGone) {
        m3912b(viewId).setVisibility(isGone ? 8 : 0);
        return this;
    }

    @NotNull
    /* renamed from: g */
    public BaseViewHolder m3917g(@IdRes int viewId, @DrawableRes int imageResId) {
        ((ImageView) m3912b(viewId)).setImageResource(imageResId);
        return this;
    }

    @NotNull
    /* renamed from: h */
    public BaseViewHolder m3918h(@IdRes int viewId, @NotNull final Function0<Unit> onClick) {
        Intrinsics.checkNotNullParameter(onClick, "onClick");
        m3912b(viewId).setOnClickListener(new View.OnClickListener() { // from class: b.b.a.a.a.o.a
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                Function0 onClick2 = Function0.this;
                int i2 = BaseViewHolder.f8893a;
                Intrinsics.checkNotNullParameter(onClick2, "$onClick");
                onClick2.invoke();
            }
        });
        return this;
    }

    @NotNull
    /* renamed from: i */
    public BaseViewHolder m3919i(@IdRes int viewId, @Nullable CharSequence value) {
        ((TextView) m3912b(viewId)).setText(value);
        return this;
    }

    @NotNull
    /* renamed from: j */
    public BaseViewHolder m3920j(@IdRes int viewId, @ColorInt int color) {
        ((TextView) m3912b(viewId)).setTextColor(color);
        return this;
    }

    @NotNull
    /* renamed from: k */
    public BaseViewHolder m3921k(@IdRes int viewId, @ColorRes int colorRes) {
        ((TextView) m3912b(viewId)).setTextColor(this.itemView.getResources().getColor(colorRes));
        return this;
    }

    @NotNull
    /* renamed from: l */
    public BaseViewHolder m3922l(@IdRes int viewId, boolean isVisible) {
        m3912b(viewId).setVisibility(isVisible ? 0 : 4);
        return this;
    }
}
