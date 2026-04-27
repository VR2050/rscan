package im.uwrkaxlmjj.messenger.utils;

import android.content.Context;
import android.widget.ImageView;
import com.bumptech.glide.Glide;
import com.bumptech.glide.load.engine.DiskCacheStrategy;
import com.bumptech.glide.load.resource.bitmap.RoundedCorners;
import com.bumptech.glide.request.BaseRequestOptions;
import com.bumptech.glide.request.RequestOptions;

/* JADX INFO: loaded from: classes2.dex */
public class ImageUtils {
    public static void LoadRoundedCornerImg(Context context, ImageView iv, Object object, int iRadius, boolean blnSkipMemoryCached, DiskCacheStrategy diskCacheStrategy, int iPlaceholderImgId, int iErrorImgId) {
        int iHeight = iv.getHeight();
        int iWidth = iv.getWidth();
        RoundedCorners roundedCorners = new RoundedCorners(iRadius);
        RequestOptions options = RequestOptions.bitmapTransform(roundedCorners).override(iWidth, iHeight).skipMemoryCache(blnSkipMemoryCached).diskCacheStrategy(diskCacheStrategy).placeholder(iPlaceholderImgId).error(iErrorImgId);
        Glide.with(context).load(object).apply((BaseRequestOptions<?>) options).into(iv);
    }

    public static void LoadRoundedCornerImg(Context context, ImageView iv, Object object, int iRadius) {
        RoundedCorners roundedCorners = new RoundedCorners(iRadius);
        RequestOptions options = RequestOptions.bitmapTransform(roundedCorners);
        Glide.with(context).load(object).apply((BaseRequestOptions<?>) options).into(iv);
    }

    public static void LoadRoundedCornerImg(Context context, ImageView iv, Object object, int iRadius, boolean blnSkipMemoryCached) {
        int iHeight = iv.getHeight();
        int iWidth = iv.getWidth();
        RoundedCorners roundedCorners = new RoundedCorners(iRadius);
        RequestOptions options = RequestOptions.bitmapTransform(roundedCorners).skipMemoryCache(blnSkipMemoryCached).override(iWidth, iHeight);
        Glide.with(context).load(object).apply((BaseRequestOptions<?>) options).into(iv);
    }

    public static void LoadRoundedCornerImg(Context context, ImageView iv, Object object, int iRadius, DiskCacheStrategy diskCacheStrategy) {
        int iHeight = iv.getHeight();
        int iWidth = iv.getWidth();
        RoundedCorners roundedCorners = new RoundedCorners(iRadius);
        RequestOptions options = RequestOptions.bitmapTransform(roundedCorners).diskCacheStrategy(diskCacheStrategy).override(iWidth, iHeight);
        Glide.with(context).load(object).apply((BaseRequestOptions<?>) options).into(iv);
    }

    public static void LoadRoundedCornerImg(Context context, ImageView iv, Object object, int iRadius, boolean blnSkipMemoryCached, DiskCacheStrategy diskCacheStrategy) {
        int iHeight = iv.getHeight();
        int iWidth = iv.getWidth();
        RoundedCorners roundedCorners = new RoundedCorners(iRadius);
        RequestOptions options = RequestOptions.bitmapTransform(roundedCorners).skipMemoryCache(blnSkipMemoryCached).diskCacheStrategy(diskCacheStrategy).override(iWidth, iHeight);
        Glide.with(context).load(object).apply((BaseRequestOptions<?>) options).into(iv);
    }

    public static void LoadRoundedCornerImg(Context context, ImageView iv, Object object, int iRadius, int iPlaceholderImgId, int iErrorImgId) {
        int iHeight = iv.getHeight();
        int iWidth = iv.getWidth();
        RoundedCorners roundedCorners = new RoundedCorners(iRadius);
        RequestOptions options = RequestOptions.bitmapTransform(roundedCorners).placeholder(iPlaceholderImgId).error(iErrorImgId).override(iWidth, iHeight);
        Glide.with(context).load(object).apply((BaseRequestOptions<?>) options).into(iv);
    }

    public static void LoadNormalImg(Context context, ImageView iv, Object object, boolean blnSkipMemoryCached, DiskCacheStrategy diskCacheStrategy, int iPlaceholderImgId, int iErrorImgId) {
        int iHeight = iv.getHeight();
        int iWidth = iv.getWidth();
        Glide.with(context).load(object).apply((BaseRequestOptions<?>) new RequestOptions().skipMemoryCache(blnSkipMemoryCached).diskCacheStrategy(diskCacheStrategy).placeholder(iPlaceholderImgId).override(iWidth, iHeight).error(iErrorImgId)).into(iv);
    }

    public static void LoadNormalImg(Context context, ImageView iv, Object object) {
        int iHeight = iv.getHeight();
        int iWidth = iv.getWidth();
        Glide.with(context).load(object).apply((BaseRequestOptions<?>) new RequestOptions().override(iWidth, iHeight)).into(iv);
    }

    public static void LoadNormalImg(Context context, ImageView iv, Object object, boolean blnSkipMemoryCached) {
        int iHeight = iv.getHeight();
        int iWidth = iv.getWidth();
        Glide.with(context).load(object).apply((BaseRequestOptions<?>) new RequestOptions().skipMemoryCache(blnSkipMemoryCached).override(iWidth, iHeight)).into(iv);
    }

    public static void LoadNormalImg(Context context, ImageView iv, Object object, DiskCacheStrategy diskCacheStrategy) {
        int iHeight = iv.getHeight();
        int iWidth = iv.getWidth();
        Glide.with(context).load(object).apply((BaseRequestOptions<?>) new RequestOptions().diskCacheStrategy(diskCacheStrategy).override(iWidth, iHeight)).into(iv);
    }

    public static void LoadNormalImg(Context context, ImageView iv, Object object, boolean blnSkipMemoryCached, DiskCacheStrategy diskCacheStrategy) {
        int iHeight = iv.getHeight();
        int iWidth = iv.getWidth();
        Glide.with(context).load(object).apply((BaseRequestOptions<?>) new RequestOptions().skipMemoryCache(blnSkipMemoryCached).diskCacheStrategy(diskCacheStrategy).override(iWidth, iHeight)).into(iv);
    }

    public static void LoadNormalImg(Context context, ImageView iv, Object object, int iPlaceholderImgId, int iErrorImgId) {
        int iHeight = iv.getHeight();
        int iWidth = iv.getWidth();
        Glide.with(context).load(object).apply((BaseRequestOptions<?>) new RequestOptions().placeholder(iPlaceholderImgId).error(iErrorImgId).override(iWidth, iHeight)).into(iv);
    }
}
