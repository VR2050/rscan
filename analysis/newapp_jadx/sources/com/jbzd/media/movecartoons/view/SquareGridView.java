package com.jbzd.media.movecartoons.view;

import android.annotation.SuppressLint;
import android.content.Context;
import android.graphics.Outline;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewOutlineProvider;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.core.internal.view.SupportMenu;
import com.google.android.material.badge.BadgeDrawable;
import com.jbzd.media.movecartoons.view.SquareGridView;
import com.luck.picture.lib.config.PictureConfig;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p143g.p144a.C1558h;
import p005b.p143g.p144a.ComponentCallbacks2C1553c;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p325v.p326a.C2818e;
import p005b.p327w.p330b.p336c.C2851b;
import p005b.p327w.p330b.p336c.C2852c;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000X\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0010\u000b\n\u0002\b\u0007\n\u0002\u0010 \n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\r\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\u0006\u0018\u00002\u00020\u0001:\u0001@B\u0011\b\u0016\u0012\u0006\u0010\u001f\u001a\u00020\u001e¢\u0006\u0004\b9\u0010:B\u001b\b\u0016\u0012\u0006\u0010\u001f\u001a\u00020\u001e\u0012\b\u0010<\u001a\u0004\u0018\u00010;¢\u0006\u0004\b9\u0010=B#\b\u0016\u0012\u0006\u0010\u001f\u001a\u00020\u001e\u0012\b\u0010<\u001a\u0004\u0018\u00010;\u0012\u0006\u0010>\u001a\u00020\u0002¢\u0006\u0004\b9\u0010?J\u0017\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0005\u0010\u0006J\u0017\u0010\n\u001a\u00020\t2\u0006\u0010\b\u001a\u00020\u0007H\u0002¢\u0006\u0004\b\n\u0010\u000bJ\u001f\u0010\f\u001a\u00020\t2\u0006\u0010\b\u001a\u00020\u00072\u0006\u0010\u0003\u001a\u00020\u0002H\u0003¢\u0006\u0004\b\f\u0010\rJ\u001f\u0010\u0010\u001a\u00020\u00042\u0006\u0010\u000e\u001a\u00020\u00022\u0006\u0010\u000f\u001a\u00020\u0002H\u0014¢\u0006\u0004\b\u0010\u0010\u0011J7\u0010\u0018\u001a\u00020\u00042\u0006\u0010\u0013\u001a\u00020\u00122\u0006\u0010\u0014\u001a\u00020\u00022\u0006\u0010\u0015\u001a\u00020\u00022\u0006\u0010\u0016\u001a\u00020\u00022\u0006\u0010\u0017\u001a\u00020\u0002H\u0014¢\u0006\u0004\b\u0018\u0010\u0019J\u001b\u0010\u001c\u001a\u00020\u00042\f\u0010\u001b\u001a\b\u0012\u0004\u0012\u00020\u00070\u001a¢\u0006\u0004\b\u001c\u0010\u001dJ\u001d\u0010!\u001a\u00020\u00022\u0006\u0010\u001f\u001a\u00020\u001e2\u0006\u0010 \u001a\u00020\u0002¢\u0006\u0004\b!\u0010\"R-\u0010)\u001a\u0012\u0012\u0004\u0012\u00020\t0#j\b\u0012\u0004\u0012\u00020\t`$8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b%\u0010&\u001a\u0004\b'\u0010(R-\u0010,\u001a\u0012\u0012\u0004\u0012\u00020\u00070#j\b\u0012\u0004\u0012\u00020\u0007`$8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b*\u0010&\u001a\u0004\b+\u0010(R\u0016\u0010-\u001a\u00020\u00028\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b-\u0010.R\u0016\u0010/\u001a\u00020\u00028\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b/\u0010.R\u0016\u00100\u001a\u00020\u00028\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b0\u0010.R\u0016\u00101\u001a\u00020\u00028\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b1\u0010.R$\u00103\u001a\u0004\u0018\u0001028\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b3\u00104\u001a\u0004\b5\u00106\"\u0004\b7\u00108¨\u0006A"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/view/SquareGridView;", "Landroid/widget/FrameLayout;", "", PictureConfig.EXTRA_DATA_COUNT, "", "calculateWidth", "(I)V", "", "s", "Landroid/view/View;", "createChildItemView", "(Ljava/lang/String;)Landroid/view/View;", "createLastChildItemView", "(Ljava/lang/String;I)Landroid/view/View;", "widthMeasureSpec", "heightMeasureSpec", "onMeasure", "(II)V", "", "changed", "left", "top", "right", "bottom", "onLayout", "(ZIIII)V", "", "data", "setUrl", "(Ljava/util/List;)V", "Landroid/content/Context;", "context", "dp", "dpToPx", "(Landroid/content/Context;I)I", "Ljava/util/ArrayList;", "Lkotlin/collections/ArrayList;", "imageViews$delegate", "Lkotlin/Lazy;", "getImageViews", "()Ljava/util/ArrayList;", "imageViews", "urls$delegate", "getUrls", "urls", "childWidth", "I", "childHeight", "childSpace", "parentWidth", "Lcom/jbzd/media/movecartoons/view/SquareGridView$OnItemClickListener;", "onItemClickListener", "Lcom/jbzd/media/movecartoons/view/SquareGridView$OnItemClickListener;", "getOnItemClickListener", "()Lcom/jbzd/media/movecartoons/view/SquareGridView$OnItemClickListener;", "setOnItemClickListener", "(Lcom/jbzd/media/movecartoons/view/SquareGridView$OnItemClickListener;)V", "<init>", "(Landroid/content/Context;)V", "Landroid/util/AttributeSet;", "attrs", "(Landroid/content/Context;Landroid/util/AttributeSet;)V", "defStyleAttr", "(Landroid/content/Context;Landroid/util/AttributeSet;I)V", "OnItemClickListener", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class SquareGridView extends FrameLayout {
    private int childHeight;
    private int childSpace;
    private int childWidth;

    /* renamed from: imageViews$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy imageViews;

    @Nullable
    private OnItemClickListener onItemClickListener;
    private int parentWidth;

    /* renamed from: urls$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy urls;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000$\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0003\bf\u0018\u00002\u00020\u0001J/\u0010\t\u001a\u00020\b2\u0016\u0010\u0005\u001a\u0012\u0012\u0004\u0012\u00020\u00030\u0002j\b\u0012\u0004\u0012\u00020\u0003`\u00042\u0006\u0010\u0007\u001a\u00020\u0006H&¢\u0006\u0004\b\t\u0010\n¨\u0006\u000b"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/view/SquareGridView$OnItemClickListener;", "", "Ljava/util/ArrayList;", "", "Lkotlin/collections/ArrayList;", "url", "", "position", "", "onItemClick", "(Ljava/util/ArrayList;I)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public interface OnItemClickListener {
        void onItemClick(@NotNull ArrayList<String> url, int position);
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public SquareGridView(@NotNull Context context) {
        super(context);
        Intrinsics.checkNotNullParameter(context, "context");
        this.urls = LazyKt__LazyJVMKt.lazy(SquareGridView$urls$2.INSTANCE);
        this.imageViews = LazyKt__LazyJVMKt.lazy(SquareGridView$imageViews$2.INSTANCE);
        Context context2 = getContext();
        Intrinsics.checkNotNullExpressionValue(context2, "context");
        this.childSpace = dpToPx(context2, 6);
    }

    private final void calculateWidth(int count) {
        char c2 = count < 3 ? (char) 3 : (char) 0;
        if (c2 == 1) {
            int i2 = this.parentWidth;
            this.childWidth = i2;
            this.childHeight = (i2 / 16) * 9;
        } else if (c2 != 2) {
            int i3 = (this.parentWidth - (this.childSpace * 2)) / 3;
            this.childWidth = i3;
            this.childHeight = i3;
        } else {
            int i4 = (this.parentWidth - this.childSpace) / 2;
            this.childWidth = i4;
            this.childHeight = (i4 / 3) * 2;
        }
    }

    private final View createChildItemView(String s) {
        ViewGroup.LayoutParams layoutParams = new ViewGroup.LayoutParams(this.childWidth, this.childHeight);
        ImageView imageView = new ImageView(getContext());
        getImageViews().add(imageView);
        imageView.setLayoutParams(layoutParams);
        imageView.setScaleType(ImageView.ScaleType.CENTER_CROP);
        C1558h mo770c = ((C2852c) ComponentCallbacks2C1553c.m739i(this)).mo770c();
        mo770c.mo763X(s);
        ((C2851b) mo770c).m3295i0().m757R(imageView);
        imageView.setOutlineProvider(new ViewOutlineProvider() { // from class: com.jbzd.media.movecartoons.view.SquareGridView$createChildItemView$1
            @Override // android.view.ViewOutlineProvider
            public void getOutline(@NotNull View view, @NotNull Outline outline) {
                Intrinsics.checkNotNullParameter(view, "view");
                Intrinsics.checkNotNullParameter(outline, "outline");
                int width = view.getWidth();
                int height = view.getHeight();
                Intrinsics.checkNotNull(SquareGridView.this.getContext());
                outline.setRoundRect(0, 0, width, height, C2354n.m2437V(r8, 5.0d));
            }
        });
        imageView.setClipToOutline(true);
        return imageView;
    }

    @SuppressLint({"SetTextI18n"})
    private final View createLastChildItemView(String s, int count) {
        StringBuilder m586H = C1499a.m586H("lastxxchileWidth :");
        m586H.append(this.childWidth);
        m586H.append(" ,chileHeight:");
        m586H.append(this.childHeight);
        m586H.append(", count:");
        m586H.append(count);
        C2818e.m3272a(m586H.toString(), new Object[0]);
        ViewGroup.LayoutParams layoutParams = new ViewGroup.LayoutParams(this.childWidth, this.childHeight);
        FrameLayout frameLayout = new FrameLayout(getContext());
        new ImageView(getContext());
        frameLayout.setLayoutParams(layoutParams);
        frameLayout.setBackgroundColor(SupportMenu.CATEGORY_MASK);
        new LinearLayout(getContext());
        TextView textView = new TextView(getContext());
        textView.setLayoutParams(new FrameLayout.LayoutParams(-2, -2));
        textView.setText(Intrinsics.stringPlus(BadgeDrawable.DEFAULT_EXCEED_MAX_BADGE_NUMBER_SUFFIX, Integer.valueOf(count)));
        textView.setTextColor(-1);
        frameLayout.addView(textView);
        getImageViews().add(frameLayout);
        return frameLayout;
    }

    private final ArrayList<View> getImageViews() {
        return (ArrayList) this.imageViews.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final ArrayList<String> getUrls() {
        return (ArrayList) this.urls.getValue();
    }

    public void _$_clearFindViewByIdCache() {
    }

    public final int dpToPx(@NotNull Context context, int dp) {
        Intrinsics.checkNotNullParameter(context, "context");
        return Math.round(dp * context.getResources().getDisplayMetrics().density);
    }

    @Nullable
    public final OnItemClickListener getOnItemClickListener() {
        return this.onItemClickListener;
    }

    @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
    public void onLayout(boolean changed, int left, int top, int right, int bottom) {
        int childCount = getChildCount();
        if (childCount <= 0) {
            return;
        }
        int i2 = 0;
        while (true) {
            int i3 = i2 + 1;
            if (getChildCount() == 2) {
                View childAt = getChildAt(i2);
                int i4 = this.childWidth;
                int i5 = this.childSpace;
                int i6 = (i4 + i5) * (i2 % 2);
                int i7 = this.childHeight;
                int i8 = (i5 + i7) * (i2 / 2);
                childAt.layout(i6, i8, i4 + i6, i7 + i8);
            } else {
                View childAt2 = getChildAt(i2);
                int i9 = this.childWidth;
                int i10 = this.childSpace;
                int i11 = (i9 + i10) * (i2 % 3);
                int i12 = this.childHeight;
                int i13 = (i10 + i12) * (i2 / 3);
                childAt2.layout(i11, i13, i9 + i11, i12 + i13);
            }
            if (i3 >= childCount) {
                return;
            } else {
                i2 = i3;
            }
        }
    }

    @Override // android.widget.FrameLayout, android.view.View
    public void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        int size = View.MeasureSpec.getSize(widthMeasureSpec);
        this.parentWidth = size;
        calculateWidth(getChildCount());
        if (getChildCount() != 0) {
            int childCount = (getChildCount() / 3) + (getChildCount() % 3 != 0 ? 1 : 0);
            r0 = ((childCount - 1) * this.childSpace) + (childCount * this.childHeight);
        }
        setMeasuredDimension(size, r0);
    }

    public final void setOnItemClickListener(@Nullable OnItemClickListener onItemClickListener) {
        this.onItemClickListener = onItemClickListener;
    }

    public final void setUrl(@NotNull List<String> data) {
        Intrinsics.checkNotNullParameter(data, "data");
        removeAllViews();
        getUrls().clear();
        getImageViews().clear();
        getUrls().addAll(data);
        calculateWidth(data.size());
        Iterator<String> it = getUrls().iterator();
        while (it.hasNext()) {
            final String s = it.next();
            Intrinsics.checkNotNullExpressionValue(s, "s");
            View createChildItemView = createChildItemView(s);
            C2354n.m2374A(createChildItemView, 0L, new Function1<View, Unit>() { // from class: com.jbzd.media.movecartoons.view.SquareGridView$setUrl$1
                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                {
                    super(1);
                }

                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(View view) {
                    invoke2(view);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@NotNull View noName_0) {
                    ArrayList<String> urls;
                    ArrayList urls2;
                    Intrinsics.checkNotNullParameter(noName_0, "$noName_0");
                    SquareGridView.OnItemClickListener onItemClickListener = SquareGridView.this.getOnItemClickListener();
                    if (onItemClickListener == null) {
                        return;
                    }
                    urls = SquareGridView.this.getUrls();
                    urls2 = SquareGridView.this.getUrls();
                    onItemClickListener.onItemClick(urls, urls2.indexOf(s));
                }
            }, 1);
            addView(createChildItemView, getChildCount(), new FrameLayout.LayoutParams(this.childWidth, this.childHeight));
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public SquareGridView(@NotNull Context context, @Nullable AttributeSet attributeSet) {
        super(context, attributeSet);
        Intrinsics.checkNotNullParameter(context, "context");
        this.urls = LazyKt__LazyJVMKt.lazy(SquareGridView$urls$2.INSTANCE);
        this.imageViews = LazyKt__LazyJVMKt.lazy(SquareGridView$imageViews$2.INSTANCE);
        Context context2 = getContext();
        Intrinsics.checkNotNullExpressionValue(context2, "context");
        this.childSpace = dpToPx(context2, 6);
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public SquareGridView(@NotNull Context context, @Nullable AttributeSet attributeSet, int i2) {
        super(context, attributeSet, i2);
        Intrinsics.checkNotNullParameter(context, "context");
        this.urls = LazyKt__LazyJVMKt.lazy(SquareGridView$urls$2.INSTANCE);
        this.imageViews = LazyKt__LazyJVMKt.lazy(SquareGridView$imageViews$2.INSTANCE);
        Context context2 = getContext();
        Intrinsics.checkNotNullExpressionValue(context2, "context");
        this.childSpace = dpToPx(context2, 6);
    }
}
