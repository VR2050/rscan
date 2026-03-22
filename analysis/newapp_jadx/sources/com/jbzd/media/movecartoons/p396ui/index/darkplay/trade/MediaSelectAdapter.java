package com.jbzd.media.movecartoons.p396ui.index.darkplay.trade;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Matrix;
import android.media.ExifInterface;
import android.os.Build;
import android.widget.ImageView;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.view.AspectRatioLayout;
import com.luck.picture.lib.entity.LocalMedia;
import com.luck.picture.lib.widget.longimage.SubsamplingScaleImageView;
import com.qnmd.adnnm.da0yzo.R;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Collection;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p005b.p143g.p144a.C1558h;
import p005b.p143g.p144a.p147m.p156v.p157c.C1704i;
import p005b.p143g.p144a.p147m.p156v.p157c.C1721z;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p325v.p326a.C2818e;
import p005b.p327w.p330b.p336c.C2851b;
import p005b.p327w.p330b.p336c.C2852c;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000:\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u001e\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\b\n\u0002\b\b\u0018\u00002\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00030\u0001:\u0001\u001bB\u0007¢\u0006\u0004\b\u0019\u0010\u001aJ\u0017\u0010\u0006\u001a\u00020\u00052\u0006\u0010\u0004\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0006\u0010\u0007J\u001f\u0010\n\u001a\u00020\t2\u0006\u0010\b\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u0002H\u0014¢\u0006\u0004\b\n\u0010\u000bJ\u001d\u0010\u000e\u001a\u00020\t2\f\u0010\r\u001a\b\u0012\u0004\u0012\u00020\u00020\fH\u0016¢\u0006\u0004\b\u000e\u0010\u000fJ\u0015\u0010\u0012\u001a\u00020\t2\u0006\u0010\u0011\u001a\u00020\u0010¢\u0006\u0004\b\u0012\u0010\u0013R\u0016\u0010\u0015\u001a\u00020\u00148\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0015\u0010\u0016R\u0016\u0010\u0017\u001a\u00020\u00108\u0002@\u0002X\u0082.¢\u0006\u0006\n\u0004\b\u0017\u0010\u0018¨\u0006\u001c"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/darkplay/trade/MediaSelectAdapter;", "Lcom/chad/library/adapter/base/BaseQuickAdapter;", "Lcom/luck/picture/lib/entity/LocalMedia;", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "item", "Ljava/io/File;", "revisedMediaFile", "(Lcom/luck/picture/lib/entity/LocalMedia;)Ljava/io/File;", "holder", "", "convert", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/luck/picture/lib/entity/LocalMedia;)V", "", "newData", "replaceData", "(Ljava/util/Collection;)V", "Lcom/jbzd/media/movecartoons/ui/index/darkplay/trade/MediaSelectAdapter$MediaType;", "type", "setupMedia", "(Lcom/jbzd/media/movecartoons/ui/index/darkplay/trade/MediaSelectAdapter$MediaType;)V", "", "maxMediaCount", "I", "mediaType", "Lcom/jbzd/media/movecartoons/ui/index/darkplay/trade/MediaSelectAdapter$MediaType;", "<init>", "()V", "MediaType", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class MediaSelectAdapter extends BaseQuickAdapter<LocalMedia, BaseViewHolder> {
    private int maxMediaCount;
    private MediaType mediaType;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001a\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\b6\u0018\u00002\u00020\u0001:\u0003\u0004\u0005\u0006B\t\b\u0004¢\u0006\u0004\b\u0002\u0010\u0003\u0082\u0001\u0003\u0007\b\t¨\u0006\n"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/darkplay/trade/MediaSelectAdapter$MediaType;", "", "<init>", "()V", "Cover", "Image", "Video", "Lcom/jbzd/media/movecartoons/ui/index/darkplay/trade/MediaSelectAdapter$MediaType$Video;", "Lcom/jbzd/media/movecartoons/ui/index/darkplay/trade/MediaSelectAdapter$MediaType$Cover;", "Lcom/jbzd/media/movecartoons/ui/index/darkplay/trade/MediaSelectAdapter$MediaType$Image;", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static abstract class MediaType {

        @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\bÆ\u0002\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003¨\u0006\u0004"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/darkplay/trade/MediaSelectAdapter$MediaType$Cover;", "Lcom/jbzd/media/movecartoons/ui/index/darkplay/trade/MediaSelectAdapter$MediaType;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
        public static final class Cover extends MediaType {

            @NotNull
            public static final Cover INSTANCE = new Cover();

            private Cover() {
                super(null);
            }
        }

        @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\bÆ\u0002\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003¨\u0006\u0004"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/darkplay/trade/MediaSelectAdapter$MediaType$Image;", "Lcom/jbzd/media/movecartoons/ui/index/darkplay/trade/MediaSelectAdapter$MediaType;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
        public static final class Image extends MediaType {

            @NotNull
            public static final Image INSTANCE = new Image();

            private Image() {
                super(null);
            }
        }

        @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\bÆ\u0002\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003¨\u0006\u0004"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/darkplay/trade/MediaSelectAdapter$MediaType$Video;", "Lcom/jbzd/media/movecartoons/ui/index/darkplay/trade/MediaSelectAdapter$MediaType;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
        public static final class Video extends MediaType {

            @NotNull
            public static final Video INSTANCE = new Video();

            private Video() {
                super(null);
            }
        }

        private MediaType() {
        }

        public /* synthetic */ MediaType(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    public MediaSelectAdapter() {
        super(R.layout.item_image_select, null, 2, null);
    }

    private final File revisedMediaFile(LocalMedia item) {
        int i2 = Build.VERSION.SDK_INT;
        int i3 = 0;
        C2818e.m3272a(Intrinsics.stringPlus("Build.VERSION.SDK_INT:", Integer.valueOf(i2)), new Object[0]);
        String path = i2 <= 28 ? item.getPath() : item.getRealPath();
        MediaType mediaType = this.mediaType;
        File file = null;
        if (mediaType == null) {
            Intrinsics.throwUninitializedPropertyAccessException("mediaType");
            throw null;
        }
        if (Intrinsics.areEqual(mediaType, MediaType.Video.INSTANCE)) {
            return new File(path);
        }
        int attributeInt = new ExifInterface(path).getAttributeInt(androidx.exifinterface.media.ExifInterface.TAG_ORIENTATION, 1);
        if (attributeInt == 3) {
            i3 = 180;
        } else if (attributeInt == 6) {
            i3 = 90;
        } else if (attributeInt == 8) {
            i3 = SubsamplingScaleImageView.ORIENTATION_270;
        }
        File file2 = new File(path);
        BitmapFactory.Options options = new BitmapFactory.Options();
        options.inJustDecodeBounds = true;
        FileInputStream fileInputStream = new FileInputStream(file2);
        BitmapFactory.decodeStream(fileInputStream, null, options);
        fileInputStream.close();
        int pow = (options.outHeight > 600 || options.outWidth > 600) ? (int) Math.pow(2.0d, (int) Math.round(Math.log(600 / Math.max(r5, options.outWidth)) / Math.log(0.5d))) : 1;
        BitmapFactory.Options options2 = new BitmapFactory.Options();
        options2.inSampleSize = pow;
        FileInputStream fileInputStream2 = new FileInputStream(file2);
        Bitmap decodeStream = BitmapFactory.decodeStream(fileInputStream2, null, options2);
        fileInputStream2.close();
        if (decodeStream != null) {
            Matrix matrix = new Matrix();
            matrix.postRotate(i3);
            Bitmap createBitmap = Bitmap.createBitmap(decodeStream, 0, 0, decodeStream.getWidth(), decodeStream.getHeight(), matrix, true);
            if (createBitmap == null) {
                createBitmap = decodeStream;
            }
            if (decodeStream != createBitmap) {
                decodeStream.recycle();
            }
            File file3 = new File(path);
            try {
                BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(file3));
                createBitmap.compress(Bitmap.CompressFormat.JPEG, 100, bufferedOutputStream);
                bufferedOutputStream.flush();
                bufferedOutputStream.close();
            } catch (IOException e2) {
                e2.printStackTrace();
            }
            file = file3;
        }
        Intrinsics.checkNotNullExpressionValue(file, "samsungPhoneSetting(path)");
        return file;
    }

    @Override // com.chad.library.adapter.base.BaseQuickAdapter
    public void replaceData(@NotNull Collection<? extends LocalMedia> newData) {
        Intrinsics.checkNotNullParameter(newData, "newData");
        super.replaceData(newData);
        if (getItemCount() < this.maxMediaCount) {
            addData((MediaSelectAdapter) new LocalMedia());
        }
    }

    public final void setupMedia(@NotNull MediaType type) {
        Intrinsics.checkNotNullParameter(type, "type");
        this.mediaType = type;
        if (type == null) {
            Intrinsics.throwUninitializedPropertyAccessException("mediaType");
            throw null;
        }
        this.maxMediaCount = Intrinsics.areEqual(type, MediaType.Image.INSTANCE) ? 9 : 1;
        notifyDataSetChanged();
    }

    @Override // com.chad.library.adapter.base.BaseQuickAdapter
    public void convert(@NotNull BaseViewHolder holder, @NotNull LocalMedia item) {
        Intrinsics.checkNotNullParameter(holder, "holder");
        Intrinsics.checkNotNullParameter(item, "item");
        MediaType mediaType = this.mediaType;
        if (mediaType == null) {
            Intrinsics.throwUninitializedPropertyAccessException("mediaType");
            throw null;
        }
        if (Intrinsics.areEqual(mediaType, MediaType.Video.INSTANCE)) {
            ((AspectRatioLayout) holder.m3912b(R.id.ll_add_select)).setBackgroundResource(R.drawable.iv_add_video);
        } else {
            ((AspectRatioLayout) holder.m3912b(R.id.ll_add_select)).setBackgroundResource(R.drawable.iv_add);
        }
        if (item.getPath() == null) {
            holder.m3912b(R.id.iv_delete).setVisibility(8);
            holder.m3912b(R.id.tv_change).setVisibility(8);
            holder.m3912b(R.id.tv_cover_img).setVisibility(8);
            ((ImageView) holder.m3912b(R.id.iv_cover)).setImageDrawable(null);
            return;
        }
        holder.m3912b(R.id.tv_change).setVisibility(0);
        holder.m3912b(R.id.iv_delete).setVisibility(0);
        C2852c m2455a2 = C2354n.m2455a2(getContext());
        File revisedMediaFile = revisedMediaFile(item);
        C1558h mo770c = m2455a2.mo770c();
        mo770c.mo760U(revisedMediaFile);
        Intrinsics.checkNotNullExpressionValue(((C2851b) ((C2851b) mo770c).mo1080J(new C1704i(), new C1721z(C2354n.m2437V(getContext(), 5.0d)))).m757R((ImageView) holder.m3912b(R.id.iv_cover)), "{\n//                    getView<TextView>(R.id.tv_change).text = when (mediaType) {\n//                        MediaType.Video -> \"更换视频\"\n//                        MediaType.Cover -> \"更换封面\"\n//                        MediaType.Image -> \"更换图片\"\n//                    }\n                    getView<ImageView>(R.id.tv_change).isVisible = true\n                    getView<ImageView>(R.id.iv_delete).isVisible = true\n\n                    GlideApp.with(context)\n                        .load(revisedMediaFile(item))\n                        .transform(CenterCrop(), RoundedCorners(DensityUtil.dpToPx(context, 5.0))\n                        ).into(getView(R.id.iv_cover))\n                }");
    }
}
