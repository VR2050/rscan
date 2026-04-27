package im.uwrkaxlmjj.ui.hui.friendscircle.glide;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.BitmapShader;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.RectF;
import android.graphics.Shader;
import android.text.TextUtils;
import android.view.View;
import android.widget.ImageView;
import com.bjz.comm.net.utils.HttpUtils;
import com.bumptech.glide.Glide;
import com.bumptech.glide.Priority;
import com.bumptech.glide.load.engine.DiskCacheStrategy;
import com.bumptech.glide.load.engine.bitmap_recycle.BitmapPool;
import com.bumptech.glide.load.model.GlideUrl;
import com.bumptech.glide.load.model.LazyHeaders;
import com.bumptech.glide.load.resource.bitmap.BitmapTransformation;
import com.bumptech.glide.load.resource.bitmap.TransformationUtils;
import com.bumptech.glide.request.RequestOptions;
import com.bumptech.glide.signature.MediaStoreSignature;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import java.security.MessageDigest;

/* JADX INFO: loaded from: classes5.dex */
public class GlideUtils {
    private static GlideUtils mInstance;
    private RequestOptions options;

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
        if (TextUtils.isEmpty(url)) {
            return;
        }
        GlideUrl glideUrl = new GlideUrl(url, new LazyHeaders.Builder().build());
        Glide.with(context).applyDefaultRequestOptions(requestOptions == null ? getOptions() : requestOptions).load((Object) glideUrl).placeholder(placeHolderResId).error(errorResourceId).centerCrop().diskCacheStrategy(DiskCacheStrategy.ALL).into(imageView);
    }

    public void load(String url, View mview, ImageView imageView, int errorResourceId) {
        GlideUrl glideUrl = new GlideUrl(url, new LazyHeaders.Builder().addHeader("User-Agent", HttpUtils.getInstance().getUserAgentFC()).build());
        Glide.with(mview).load((Object) glideUrl).error(errorResourceId).centerCrop().diskCacheStrategy(DiskCacheStrategy.ALL).into(imageView);
    }

    public void loadVideoThumb(String url, View mview, ImageView imageView, int errorResourceId) {
        GlideUrl glideUrl = new GlideUrl(url, new LazyHeaders.Builder().addHeader("User-Agent", HttpUtils.getInstance().getUserAgentFC()).build());
        Glide.with(mview).load((Object) glideUrl).error(errorResourceId).centerCrop().diskCacheStrategy(DiskCacheStrategy.ALL).into(imageView);
    }

    public void loadNOCentercrop(String url, View mview, ImageView imageView, int errorResourceId) {
        GlideUrl glideUrl = new GlideUrl(url, new LazyHeaders.Builder().addHeader("User-Agent", HttpUtils.getInstance().getUserAgentFC()).build());
        Glide.with(mview).load((Object) glideUrl).error(errorResourceId).diskCacheStrategy(DiskCacheStrategy.ALL).into(imageView);
    }

    public void loadWithRadius(Context context, String url, ImageView imageView, int errorResourceId, int radius) {
        GlideUrl glideUrl = new GlideUrl(url, new LazyHeaders.Builder().addHeader("User-Agent", HttpUtils.getInstance().getUserAgentFC()).build());
        if (radius < 0) {
            radius = 0;
        }
        GlideRoundTransform glideRoundTransform = new GlideRoundTransform(AndroidUtilities.dp(radius));
        Glide.with(context).load(url.startsWith("http") ? glideUrl : url).error(errorResourceId).transform(glideRoundTransform).into(imageView);
    }

    public void loadWithRadiusNoCache(Context context, String url, ImageView imageView, int errorResourceId, int radius) {
        GlideUrl glideUrl = new GlideUrl(url, new LazyHeaders.Builder().addHeader("User-Agent", HttpUtils.getInstance().getUserAgentFC()).build());
        if (radius < 0) {
            radius = 0;
        }
        GlideRoundTransform glideRoundTransform = new GlideRoundTransform(AndroidUtilities.dp(radius));
        Glide.with(context).load(url.startsWith("http") ? glideUrl : url).error(errorResourceId).transform(glideRoundTransform).signature(new MediaStoreSignature("img/jpg", System.currentTimeMillis(), 1)).into(imageView);
    }

    public class GlideRoundTransform extends BitmapTransformation {
        private float radius;

        public GlideRoundTransform(int dp) {
            this.radius = 0.0f;
            this.radius = dp;
        }

        @Override // com.bumptech.glide.load.resource.bitmap.BitmapTransformation
        protected Bitmap transform(BitmapPool pool, Bitmap toTransform, int outWidth, int outHeight) {
            Bitmap bitmap = TransformationUtils.centerCrop(pool, toTransform, outWidth, outHeight);
            return roundCrop(pool, bitmap);
        }

        private Bitmap roundCrop(BitmapPool pool, Bitmap source) {
            if (source == null) {
                return null;
            }
            Bitmap result = pool.get(source.getWidth(), source.getHeight(), Bitmap.Config.ARGB_8888);
            if (result == null) {
                result = Bitmap.createBitmap(source.getWidth(), source.getHeight(), Bitmap.Config.ARGB_8888);
            }
            Canvas canvas = new Canvas(result);
            Paint paint = new Paint();
            paint.setShader(new BitmapShader(source, Shader.TileMode.CLAMP, Shader.TileMode.CLAMP));
            paint.setAntiAlias(true);
            RectF rectF = new RectF(0.0f, 0.0f, source.getWidth(), source.getHeight());
            float f = this.radius;
            canvas.drawRoundRect(rectF, f, f, paint);
            return result;
        }

        public String getId() {
            return getClass().getName() + Math.round(this.radius);
        }

        @Override // com.bumptech.glide.load.Key
        public void updateDiskCacheKey(MessageDigest messageDigest) {
        }
    }
}
