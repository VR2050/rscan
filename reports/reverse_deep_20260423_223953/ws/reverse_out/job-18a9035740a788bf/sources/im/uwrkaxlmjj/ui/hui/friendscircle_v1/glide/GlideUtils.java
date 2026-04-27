package im.uwrkaxlmjj.ui.hui.friendscircle_v1.glide;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.Drawable;
import android.widget.ImageView;
import androidx.core.graphics.drawable.RoundedBitmapDrawable;
import androidx.core.graphics.drawable.RoundedBitmapDrawableFactory;
import com.bjz.comm.net.utils.HttpUtils;
import com.bumptech.glide.Glide;
import com.bumptech.glide.Priority;
import com.bumptech.glide.RequestBuilder;
import com.bumptech.glide.load.engine.DiskCacheStrategy;
import com.bumptech.glide.load.model.GlideUrl;
import com.bumptech.glide.load.model.LazyHeaders;
import com.bumptech.glide.request.BaseRequestOptions;
import com.bumptech.glide.request.RequestOptions;
import com.bumptech.glide.request.target.ImageViewTarget;
import com.bumptech.glide.request.target.SimpleTarget;
import com.bumptech.glide.request.transition.Transition;
import im.uwrkaxlmjj.messenger.AndroidUtilities;

/* JADX INFO: loaded from: classes5.dex */
@Deprecated
public class GlideUtils {
    private static GlideUtils mInstance;
    private interGetDrawable GetDrawableListener;
    private RequestOptions options;
    SimpleTarget<Drawable> simpleTarget = new SimpleTarget<Drawable>() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.glide.GlideUtils.1
        @Override // com.bumptech.glide.request.target.Target
        public /* bridge */ /* synthetic */ void onResourceReady(Object obj, Transition transition) {
            onResourceReady((Drawable) obj, (Transition<? super Drawable>) transition);
        }

        public void onResourceReady(Drawable resource, Transition<? super Drawable> transition) {
            if (GlideUtils.this.GetDrawableListener != null) {
                GlideUtils.this.GetDrawableListener.onGetDrawable(resource);
            }
        }
    };

    public interface interGetDrawable {
        void onGetDrawable(Drawable drawable);
    }

    public static GlideUtils getInstance() {
        if (mInstance == null) {
            synchronized (GlideUtils.class) {
                if (mInstance == null) {
                    mInstance = new GlideUtils();
                }
            }
        }
        return mInstance;
    }

    public RequestOptions getOptions() {
        if (this.options == null) {
            this.options = RequestOptions.priorityOf(Priority.NORMAL);
        }
        return this.options;
    }

    public void load(int resId, Context context, ImageView imageView, int errorResourceId) {
        load(resId, context, imageView, errorResourceId, 0);
    }

    public void load(int resId, Context context, ImageView imageView, int errorResourceId, int placeHolderResId) {
        load(resId, context, imageView, errorResourceId, placeHolderResId, getOptions());
    }

    public void load(int resId, Context context, ImageView imageView, int errorResourceId, RequestOptions requestOptions) {
        load(resId, context, imageView, errorResourceId, 0, requestOptions);
    }

    public void load(int resId, Context context, ImageView imageView, int errorResourceId, int placeHolderResId, RequestOptions requestOptions) {
        Glide.with(context).applyDefaultRequestOptions(requestOptions == null ? getOptions() : requestOptions).load(Integer.valueOf(resId)).placeholder(placeHolderResId).error(errorResourceId).centerCrop().diskCacheStrategy(DiskCacheStrategy.ALL).into(imageView);
    }

    public void load(String url, Context context, ImageView imageView, int errorResourceId) {
        load(url, context, imageView, errorResourceId, 0);
    }

    public void load(String url, Context context, ImageView imageView, int errorResourceId, int placeHolderResId) {
        load(url, context, imageView, errorResourceId, placeHolderResId, getOptions());
    }

    public void load(String url, Context context, ImageView imageView, int errorResourceId, RequestOptions requestOptions) {
        load(url, context, imageView, errorResourceId, 0, requestOptions);
    }

    public void load(String url, Context context, ImageView imageView, int errorResourceId, int placeHolderResId, RequestOptions requestOptions) {
        GlideUrl glideUrl = new GlideUrl(url, new LazyHeaders.Builder().build());
        Glide.with(context).applyDefaultRequestOptions(requestOptions == null ? getOptions() : requestOptions).load((Object) glideUrl).placeholder(placeHolderResId).error(errorResourceId).centerCrop().diskCacheStrategy(DiskCacheStrategy.ALL).into(imageView);
    }

    public void loadLocal(String localPath, Context context, ImageView imageView, int errorResourceId) {
        Glide.with(context).applyDefaultRequestOptions(getOptions()).load(localPath).error(errorResourceId).centerCrop().diskCacheStrategy(DiskCacheStrategy.ALL).into(imageView);
    }

    public void loadNOCentercrop(String url, Context context, ImageView imageView, int errorResourceId) {
        GlideUrl glideUrl = new GlideUrl(url, new LazyHeaders.Builder().addHeader("User-Agent", HttpUtils.getInstance().getUserAgentFC()).build());
        Glide.with(context).applyDefaultRequestOptions(getOptions()).load((Object) glideUrl).error(errorResourceId).diskCacheStrategy(DiskCacheStrategy.ALL).into(imageView);
    }

    public void loadWithRadius(Context context, String url, ImageView imageView, int errorResourceId, int radius) {
        GlideUrl glideUrl = new GlideUrl(url, new LazyHeaders.Builder().addHeader("User-Agent", HttpUtils.getInstance().getUserAgentFC()).build());
        if (radius < 0) {
            radius = 0;
        }
        GlideRoundTransform glideRoundTransform = new GlideRoundTransform(AndroidUtilities.dp(radius));
        Glide.with(context).load((Object) glideUrl).error(errorResourceId).transform(glideRoundTransform).diskCacheStrategy(DiskCacheStrategy.ALL).into(imageView);
    }

    public void LoadCircleImg(Context context, ImageView iv, String strPath, boolean blnSkipMemoryCached, int iDefImgId) {
        int iHeight = iv.getHeight();
        int iWidth = iv.getWidth();
        RequestOptions mRequestOptions = RequestOptions.circleCropTransform().skipMemoryCache(blnSkipMemoryCached).override(iWidth, iHeight).error(iDefImgId).placeholder(iDefImgId);
        RequestBuilder<Bitmap> glideRequest = Glide.with(context).asBitmap();
        glideRequest.load(strPath).apply((BaseRequestOptions<?>) mRequestOptions).into(new GlideCircleTransform(iv));
    }

    public void loadDrawableFromUrl(Context context, String strUrl, interGetDrawable getDrawable) {
        this.GetDrawableListener = getDrawable;
        Glide.with(context).load(strUrl).skipMemoryCache(false).into(this.simpleTarget);
    }

    public void setGetDrawableListener(interGetDrawable getDrawableListener) {
        this.GetDrawableListener = getDrawableListener;
    }

    public static class GlideCircleTransform extends ImageViewTarget<Bitmap> {
        public GlideCircleTransform(ImageView view) {
            super(view);
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.bumptech.glide.request.target.ImageViewTarget
        public void setResource(Bitmap resource) {
            bindCircleBitmapToImageView(resource);
        }

        @Override // com.bumptech.glide.request.target.ImageViewTarget, com.bumptech.glide.request.transition.Transition.ViewAdapter
        public void setDrawable(Drawable drawable) {
            if (drawable instanceof BitmapDrawable) {
                Bitmap bitmap1 = ((BitmapDrawable) drawable).getBitmap();
                bindCircleBitmapToImageView(bitmap1);
            } else {
                ((ImageView) this.view).setImageDrawable(drawable);
            }
        }

        private void bindCircleBitmapToImageView(Bitmap bitmap) {
            RoundedBitmapDrawable bitmapDrawable = RoundedBitmapDrawableFactory.create(((ImageView) this.view).getContext().getResources(), bitmap);
            bitmapDrawable.setCircular(true);
            ((ImageView) this.view).setImageDrawable(bitmapDrawable);
        }
    }
}
