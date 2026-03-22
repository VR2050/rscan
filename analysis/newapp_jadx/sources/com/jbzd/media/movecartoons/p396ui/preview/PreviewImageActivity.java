package com.jbzd.media.movecartoons.p396ui.preview;

import android.app.Application;
import android.content.Context;
import android.content.Intent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.viewpager.widget.PagerAdapter;
import androidx.viewpager.widget.ViewPager;
import com.alibaba.fastjson.asm.Label;
import com.github.chrisbanes.photoview.PhotoView;
import com.gyf.immersionbar.ImmersionBar;
import com.jbzd.media.movecartoons.p396ui.preview.PreviewImageActivity$adapter$2;
import com.jbzd.media.movecartoons.view.HackyViewPager;
import com.jbzd.media.movecartoons.view.SlideCloseLayout;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.core.view.BaseActivity;
import java.util.List;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000@\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0007\u0018\u0000 %2\u00020\u0001:\u0001%B\u0007¢\u0006\u0004\b$\u0010\u0004J\u000f\u0010\u0003\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0003\u0010\u0004J\u000f\u0010\u0005\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0005\u0010\u0004J\u000f\u0010\u0007\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u0007\u0010\bJ\u000f\u0010\t\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\t\u0010\u0004R\u001d\u0010\u000f\u001a\u00020\n8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u000b\u0010\f\u001a\u0004\b\r\u0010\u000eR\u001d\u0010\u0014\u001a\u00020\u00108F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0011\u0010\f\u001a\u0004\b\u0012\u0010\u0013R\u001d\u0010\u0019\u001a\u00020\u00158F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0016\u0010\f\u001a\u0004\b\u0017\u0010\u0018R\u001d\u0010\u001e\u001a\u00020\u001a8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u001b\u0010\f\u001a\u0004\b\u001c\u0010\u001dR\u001d\u0010#\u001a\u00020\u001f8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b \u0010\f\u001a\u0004\b!\u0010\"¨\u0006&"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/preview/PreviewImageActivity;", "Lcom/qunidayede/supportlibrary/core/view/BaseActivity;", "", "initStatusBar", "()V", "bindEvent", "", "getLayoutId", "()I", "onBackPressed", "Landroid/widget/RelativeLayout;", "btn_titleBack$delegate", "Lkotlin/Lazy;", "getBtn_titleBack", "()Landroid/widget/RelativeLayout;", "btn_titleBack", "Landroidx/viewpager/widget/PagerAdapter;", "adapter$delegate", "getAdapter", "()Landroidx/viewpager/widget/PagerAdapter;", "adapter", "Lcom/jbzd/media/movecartoons/view/HackyViewPager;", "vp_image$delegate", "getVp_image", "()Lcom/jbzd/media/movecartoons/view/HackyViewPager;", "vp_image", "Lcom/jbzd/media/movecartoons/view/SlideCloseLayout;", "slide_close_layout$delegate", "getSlide_close_layout", "()Lcom/jbzd/media/movecartoons/view/SlideCloseLayout;", "slide_close_layout", "Landroid/widget/TextView;", "tv_index$delegate", "getTv_index", "()Landroid/widget/TextView;", "tv_index", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class PreviewImageActivity extends BaseActivity {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);
    public static List<String> imageList;
    private static int index;

    /* renamed from: btn_titleBack$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy btn_titleBack = LazyKt__LazyJVMKt.lazy(new Function0<RelativeLayout>() { // from class: com.jbzd.media.movecartoons.ui.preview.PreviewImageActivity$btn_titleBack$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final RelativeLayout invoke() {
            RelativeLayout relativeLayout = (RelativeLayout) PreviewImageActivity.this.findViewById(R.id.btn_titleBack);
            Intrinsics.checkNotNull(relativeLayout);
            return relativeLayout;
        }
    });

    /* renamed from: slide_close_layout$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy slide_close_layout = LazyKt__LazyJVMKt.lazy(new Function0<SlideCloseLayout>() { // from class: com.jbzd.media.movecartoons.ui.preview.PreviewImageActivity$slide_close_layout$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final SlideCloseLayout invoke() {
            SlideCloseLayout slideCloseLayout = (SlideCloseLayout) PreviewImageActivity.this.findViewById(R.id.slide_close_layout);
            Intrinsics.checkNotNull(slideCloseLayout);
            return slideCloseLayout;
        }
    });

    /* renamed from: tv_index$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_index = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.preview.PreviewImageActivity$tv_index$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) PreviewImageActivity.this.findViewById(R.id.tv_index);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: vp_image$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy vp_image = LazyKt__LazyJVMKt.lazy(new Function0<HackyViewPager>() { // from class: com.jbzd.media.movecartoons.ui.preview.PreviewImageActivity$vp_image$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final HackyViewPager invoke() {
            HackyViewPager hackyViewPager = (HackyViewPager) PreviewImageActivity.this.findViewById(R.id.vp_image);
            Intrinsics.checkNotNull(hackyViewPager);
            return hackyViewPager;
        }
    });

    /* renamed from: adapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy adapter = LazyKt__LazyJVMKt.lazy(new Function0<PreviewImageActivity$adapter$2.C38691>() { // from class: com.jbzd.media.movecartoons.ui.preview.PreviewImageActivity$adapter$2
        /* JADX WARN: Can't rename method to resolve collision */
        /* JADX WARN: Type inference failed for: r0v0, types: [com.jbzd.media.movecartoons.ui.preview.PreviewImageActivity$adapter$2$1] */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final C38691 invoke() {
            return new PagerAdapter() { // from class: com.jbzd.media.movecartoons.ui.preview.PreviewImageActivity$adapter$2.1
                @Override // androidx.viewpager.widget.PagerAdapter
                public void destroyItem(@NotNull ViewGroup container, int position, @NotNull Object object) {
                    Intrinsics.checkNotNullParameter(container, "container");
                    Intrinsics.checkNotNullParameter(object, "object");
                    container.removeView((View) object);
                }

                @Override // androidx.viewpager.widget.PagerAdapter
                public int getCount() {
                    return PreviewImageActivity.INSTANCE.getImageList().size();
                }

                @Override // androidx.viewpager.widget.PagerAdapter
                @NotNull
                public Object instantiateItem(@NotNull ViewGroup container, int position) {
                    Intrinsics.checkNotNullParameter(container, "container");
                    PhotoView photoView = new PhotoView(container.getContext());
                    C2354n.m2455a2(container.getContext()).m3298p(PreviewImageActivity.INSTANCE.getImageList().get(position)).m3295i0().m757R(photoView);
                    container.addView(photoView, -1, -1);
                    return photoView;
                }

                @Override // androidx.viewpager.widget.PagerAdapter
                public boolean isViewFromObject(@NotNull View view, @NotNull Object object) {
                    Intrinsics.checkNotNullParameter(view, "view");
                    Intrinsics.checkNotNullParameter(object, "object");
                    return Intrinsics.areEqual(view, object);
                }
            };
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000&\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0010 \n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0011\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0018\u0010\u0019J+\u0010\n\u001a\u00020\t2\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u00042\f\u0010\b\u001a\b\u0012\u0004\u0012\u00020\u00070\u0006¢\u0006\u0004\b\n\u0010\u000bR\"\u0010\f\u001a\u00020\u00048\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\f\u0010\r\u001a\u0004\b\u000e\u0010\u000f\"\u0004\b\u0010\u0010\u0011R(\u0010\u0012\u001a\b\u0012\u0004\u0012\u00020\u00070\u00068\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\b\u0012\u0010\u0013\u001a\u0004\b\u0014\u0010\u0015\"\u0004\b\u0016\u0010\u0017¨\u0006\u001a"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/preview/PreviewImageActivity$Companion;", "", "Landroid/content/Context;", "context", "", "position", "", "", "list", "", "start", "(Landroid/content/Context;ILjava/util/List;)V", "index", "I", "getIndex", "()I", "setIndex", "(I)V", "imageList", "Ljava/util/List;", "getImageList", "()Ljava/util/List;", "setImageList", "(Ljava/util/List;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final List<String> getImageList() {
            List<String> list = PreviewImageActivity.imageList;
            if (list != null) {
                return list;
            }
            Intrinsics.throwUninitializedPropertyAccessException("imageList");
            throw null;
        }

        public final int getIndex() {
            return PreviewImageActivity.index;
        }

        public final void setImageList(@NotNull List<String> list) {
            Intrinsics.checkNotNullParameter(list, "<set-?>");
            PreviewImageActivity.imageList = list;
        }

        public final void setIndex(int i2) {
            PreviewImageActivity.index = i2;
        }

        public final void start(@NotNull Context context, int position, @NotNull List<String> list) {
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(list, "list");
            setIndex(position);
            setImageList(list);
            Intent intent = new Intent(context, (Class<?>) PreviewImageActivity.class);
            if (context instanceof Application) {
                intent.addFlags(Label.FORWARD_REFERENCE_TYPE_SHORT);
            }
            context.startActivity(intent);
        }
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public void bindEvent() {
        C2354n.m2374A(getBtn_titleBack(), 0L, new Function1<RelativeLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.preview.PreviewImageActivity$bindEvent$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(RelativeLayout relativeLayout) {
                invoke2(relativeLayout);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull RelativeLayout it) {
                Intrinsics.checkNotNullParameter(it, "it");
                PreviewImageActivity.this.onBackPressed();
            }
        }, 1);
        SlideCloseLayout slide_close_layout = getSlide_close_layout();
        slide_close_layout.setBackground(getWindow().getDecorView().getBackground());
        slide_close_layout.setScrollListener(new SlideCloseLayout.LayoutScrollListener() { // from class: com.jbzd.media.movecartoons.ui.preview.PreviewImageActivity$bindEvent$2$1
            @Override // com.jbzd.media.movecartoons.view.SlideCloseLayout.LayoutScrollListener
            public void onLayoutClosed() {
                PreviewImageActivity.this.onBackPressed();
            }

            @Override // com.jbzd.media.movecartoons.view.SlideCloseLayout.LayoutScrollListener
            public void onLayoutScrollRevocer() {
                PreviewImageActivity.this.getTv_index().setAlpha(1.0f);
            }

            @Override // com.jbzd.media.movecartoons.view.SlideCloseLayout.LayoutScrollListener
            public void onLayoutScrolling(float alpha) {
                PreviewImageActivity.this.getTv_index().setAlpha(1 - (alpha * 5.0f));
            }
        });
        getTv_index().setText(Intrinsics.stringPlus("1/", Integer.valueOf(INSTANCE.getImageList().size())));
        HackyViewPager vp_image = getVp_image();
        vp_image.setAdapter(getAdapter());
        vp_image.addOnPageChangeListener(new ViewPager.OnPageChangeListener() { // from class: com.jbzd.media.movecartoons.ui.preview.PreviewImageActivity$bindEvent$3$1
            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageScrollStateChanged(int state) {
            }

            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
            }

            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageSelected(int position) {
                TextView tv_index = PreviewImageActivity.this.getTv_index();
                StringBuilder sb = new StringBuilder();
                sb.append(position + 1);
                sb.append('/');
                sb.append(PreviewImageActivity.INSTANCE.getImageList().size());
                tv_index.setText(sb.toString());
            }
        });
        getVp_image().setCurrentItem(index, false);
    }

    @NotNull
    public final PagerAdapter getAdapter() {
        return (PagerAdapter) this.adapter.getValue();
    }

    @NotNull
    public final RelativeLayout getBtn_titleBack() {
        return (RelativeLayout) this.btn_titleBack.getValue();
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public int getLayoutId() {
        return R.layout.preview_image_act;
    }

    @NotNull
    public final SlideCloseLayout getSlide_close_layout() {
        return (SlideCloseLayout) this.slide_close_layout.getValue();
    }

    @NotNull
    public final TextView getTv_index() {
        return (TextView) this.tv_index.getValue();
    }

    @NotNull
    public final HackyViewPager getVp_image() {
        return (HackyViewPager) this.vp_image.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    public void initStatusBar() {
        ImmersionBar.with(this).navigationBarColor("#000000").statusBarDarkFont(true).init();
    }

    @Override // androidx.activity.ComponentActivity, android.app.Activity
    public void onBackPressed() {
        finish();
        overridePendingTransition(R.anim.preview_fade_in, R.anim.preview_fade_out);
    }
}
