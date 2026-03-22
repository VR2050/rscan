package p005b.p006a.p007a.p008a.p009a;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.PointF;
import android.graphics.drawable.Drawable;
import android.widget.ImageView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.graphics.drawable.RoundedBitmapDrawable;
import androidx.core.graphics.drawable.RoundedBitmapDrawableFactory;
import com.luck.picture.lib.engine.ImageEngine;
import com.luck.picture.lib.listener.OnImageCompleteCallback;
import com.luck.picture.lib.tools.MediaUtils;
import com.luck.picture.lib.widget.longimage.ImageSource;
import com.luck.picture.lib.widget.longimage.ImageViewState;
import com.luck.picture.lib.widget.longimage.SubsamplingScaleImageView;
import com.qnmd.adnnm.da0yzo.R;
import p005b.p143g.p144a.ComponentCallbacks2C1553c;
import p005b.p143g.p144a.p166q.C1779f;
import p005b.p143g.p144a.p166q.p167i.AbstractC1787f;
import p005b.p143g.p144a.p166q.p167i.C1783b;

/* renamed from: b.a.a.a.a.w */
/* loaded from: classes2.dex */
public class C0875w implements ImageEngine {

    /* renamed from: a */
    public static C0875w f312a;

    /* renamed from: b.a.a.a.a.w$a */
    public class a extends AbstractC1787f<Bitmap> {

        /* renamed from: h */
        public final /* synthetic */ OnImageCompleteCallback f313h;

        /* renamed from: i */
        public final /* synthetic */ SubsamplingScaleImageView f314i;

        /* renamed from: j */
        public final /* synthetic */ ImageView f315j;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public a(C0875w c0875w, ImageView imageView, OnImageCompleteCallback onImageCompleteCallback, SubsamplingScaleImageView subsamplingScaleImageView, ImageView imageView2) {
            super(imageView);
            this.f313h = onImageCompleteCallback;
            this.f314i = subsamplingScaleImageView;
            this.f315j = imageView2;
        }

        @Override // p005b.p143g.p144a.p166q.p167i.AbstractC1787f
        /* renamed from: a */
        public void mo205a(@Nullable Bitmap bitmap) {
            Bitmap bitmap2 = bitmap;
            OnImageCompleteCallback onImageCompleteCallback = this.f313h;
            if (onImageCompleteCallback != null) {
                onImageCompleteCallback.onHideLoading();
            }
            if (bitmap2 != null) {
                boolean isLongImg = MediaUtils.isLongImg(bitmap2.getWidth(), bitmap2.getHeight());
                this.f314i.setVisibility(isLongImg ? 0 : 8);
                this.f315j.setVisibility(isLongImg ? 8 : 0);
                if (!isLongImg) {
                    this.f315j.setImageBitmap(bitmap2);
                    return;
                }
                this.f314i.setQuickScaleEnabled(true);
                this.f314i.setZoomEnabled(true);
                this.f314i.setDoubleTapZoomDuration(100);
                this.f314i.setMinimumScaleType(2);
                this.f314i.setDoubleTapZoomDpi(2);
                this.f314i.setImage(ImageSource.bitmap(bitmap2), new ImageViewState(0.0f, new PointF(0.0f, 0.0f), 0));
            }
        }

        @Override // p005b.p143g.p144a.p166q.p167i.AbstractC1787f, p005b.p143g.p144a.p166q.p167i.InterfaceC1790i
        public void onLoadFailed(@Nullable Drawable drawable) {
            m1128b(null);
            ((ImageView) this.f2729e).setImageDrawable(drawable);
            OnImageCompleteCallback onImageCompleteCallback = this.f313h;
            if (onImageCompleteCallback != null) {
                onImageCompleteCallback.onHideLoading();
            }
        }

        @Override // p005b.p143g.p144a.p166q.p167i.AbstractC1787f, p005b.p143g.p144a.p166q.p167i.InterfaceC1790i
        public void onLoadStarted(@Nullable Drawable drawable) {
            m1128b(null);
            ((ImageView) this.f2729e).setImageDrawable(drawable);
            OnImageCompleteCallback onImageCompleteCallback = this.f313h;
            if (onImageCompleteCallback != null) {
                onImageCompleteCallback.onShowLoading();
            }
        }
    }

    /* renamed from: b.a.a.a.a.w$b */
    public class b extends AbstractC1787f<Bitmap> {

        /* renamed from: h */
        public final /* synthetic */ SubsamplingScaleImageView f316h;

        /* renamed from: i */
        public final /* synthetic */ ImageView f317i;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public b(C0875w c0875w, ImageView imageView, SubsamplingScaleImageView subsamplingScaleImageView, ImageView imageView2) {
            super(imageView);
            this.f316h = subsamplingScaleImageView;
            this.f317i = imageView2;
        }

        @Override // p005b.p143g.p144a.p166q.p167i.AbstractC1787f
        /* renamed from: a */
        public void mo205a(@Nullable Bitmap bitmap) {
            Bitmap bitmap2 = bitmap;
            if (bitmap2 != null) {
                boolean isLongImg = MediaUtils.isLongImg(bitmap2.getWidth(), bitmap2.getHeight());
                this.f316h.setVisibility(isLongImg ? 0 : 8);
                this.f317i.setVisibility(isLongImg ? 8 : 0);
                if (!isLongImg) {
                    this.f317i.setImageBitmap(bitmap2);
                    return;
                }
                this.f316h.setQuickScaleEnabled(true);
                this.f316h.setZoomEnabled(true);
                this.f316h.setDoubleTapZoomDuration(100);
                this.f316h.setMinimumScaleType(2);
                this.f316h.setDoubleTapZoomDpi(2);
                this.f316h.setImage(ImageSource.bitmap(bitmap2), new ImageViewState(0.0f, new PointF(0.0f, 0.0f), 0));
            }
        }
    }

    /* renamed from: b.a.a.a.a.w$c */
    public class c extends C1783b {

        /* renamed from: h */
        public final /* synthetic */ Context f318h;

        /* renamed from: i */
        public final /* synthetic */ ImageView f319i;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public c(C0875w c0875w, ImageView imageView, Context context, ImageView imageView2) {
            super(imageView);
            this.f318h = context;
            this.f319i = imageView2;
        }

        @Override // p005b.p143g.p144a.p166q.p167i.C1783b, p005b.p143g.p144a.p166q.p167i.AbstractC1787f
        /* renamed from: a */
        public void mo205a(Bitmap bitmap) {
            RoundedBitmapDrawable create = RoundedBitmapDrawableFactory.create(this.f318h.getResources(), bitmap);
            create.setCornerRadius(8.0f);
            this.f319i.setImageDrawable(create);
        }

        @Override // p005b.p143g.p144a.p166q.p167i.C1783b
        /* renamed from: c */
        public void mo205a(Bitmap bitmap) {
            RoundedBitmapDrawable create = RoundedBitmapDrawableFactory.create(this.f318h.getResources(), bitmap);
            create.setCornerRadius(8.0f);
            this.f319i.setImageDrawable(create);
        }
    }

    /* renamed from: a */
    public static C0875w m204a() {
        if (f312a == null) {
            synchronized (C0875w.class) {
                if (f312a == null) {
                    f312a = new C0875w();
                }
            }
        }
        return f312a;
    }

    @Override // com.luck.picture.lib.engine.ImageEngine
    public void loadAsGifImage(@NonNull Context context, @NonNull String str, @NonNull ImageView imageView) {
        ComponentCallbacks2C1553c.m738h(context).mo771d().mo763X(str).m757R(imageView);
    }

    @Override // com.luck.picture.lib.engine.ImageEngine
    public void loadFolderImage(@NonNull Context context, @NonNull String str, @NonNull ImageView imageView) {
        ComponentCallbacks2C1553c.m738h(context).mo769b().mo763X(str).mo1097x(180, 180).mo1083d().mo1074D(0.5f).mo766a(new C1779f().mo1098y(R.drawable.picture_image_placeholder)).m755P(new c(this, imageView, context, imageView));
    }

    @Override // com.luck.picture.lib.engine.ImageEngine
    public void loadGridImage(@NonNull Context context, @NonNull String str, @NonNull ImageView imageView) {
        ComponentCallbacks2C1553c.m738h(context).mo775h(str).mo1097x(200, 200).mo1083d().mo766a(new C1779f().mo1098y(R.drawable.picture_image_placeholder)).m757R(imageView);
    }

    @Override // com.luck.picture.lib.engine.ImageEngine
    public void loadImage(@NonNull Context context, @NonNull String str, @NonNull ImageView imageView) {
        ComponentCallbacks2C1553c.m738h(context).mo775h(str).m757R(imageView);
    }

    @Override // com.luck.picture.lib.engine.ImageEngine
    public void loadImage(@NonNull Context context, @NonNull String str, @NonNull ImageView imageView, SubsamplingScaleImageView subsamplingScaleImageView, OnImageCompleteCallback onImageCompleteCallback) {
        ComponentCallbacks2C1553c.m738h(context).mo769b().mo763X(str).m755P(new a(this, imageView, onImageCompleteCallback, subsamplingScaleImageView, imageView));
    }

    @Override // com.luck.picture.lib.engine.ImageEngine
    public void loadImage(@NonNull Context context, @NonNull String str, @NonNull ImageView imageView, SubsamplingScaleImageView subsamplingScaleImageView) {
        ComponentCallbacks2C1553c.m738h(context).mo769b().mo763X(str).m755P(new b(this, imageView, subsamplingScaleImageView, imageView));
    }
}
