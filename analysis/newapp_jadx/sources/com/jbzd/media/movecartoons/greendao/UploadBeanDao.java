package com.jbzd.media.movecartoons.greendao;

import android.database.Cursor;
import androidx.core.app.NotificationCompat;
import com.jbzd.media.movecartoons.bean.response.UploadBean;
import com.jbzd.media.movecartoons.bean.response.VideoTypeBean;
import com.jbzd.media.movecartoons.p396ui.index.home.child.VideoListActivity;
import p005b.p006a.p007a.p008a.p016q.C0914d;
import p476m.p496b.p500b.AbstractC4926a;
import p476m.p496b.p500b.C4930e;
import p476m.p496b.p500b.p503h.C4942a;

/* loaded from: classes2.dex */
public class UploadBeanDao extends AbstractC4926a<UploadBean, Long> {
    public static final String TABLENAME = "UPLOAD_BEAN";

    public static class Properties {
        public static final C4930e Progress_slice;
        public static final C4930e Total_slices;

        /* renamed from: Id */
        public static final C4930e f10062Id = new C4930e(0, Long.class, "id", true, "_id");
        public static final C4930e Title = new C4930e(1, String.class, VideoListActivity.KEY_TITLE, false, "TITLE");
        public static final C4930e Img = new C4930e(2, String.class, "img", false, "IMG");
        public static final C4930e Preview = new C4930e(3, String.class, "preview", false, "PREVIEW");
        public static final C4930e Preview_m3u8_url = new C4930e(4, String.class, "preview_m3u8_url", false, "PREVIEW_M3U8_URL");
        public static final C4930e M3u8_url = new C4930e(5, String.class, "m3u8_url", false, "M3U8_URL");
        public static final C4930e Duration = new C4930e(6, String.class, "duration", false, "DURATION");
        public static final C4930e Quality = new C4930e(7, String.class, "quality", false, "QUALITY");
        public static final C4930e Img_show = new C4930e(8, String.class, "img_show", false, "IMG_SHOW");
        public static final C4930e Point = new C4930e(9, String.class, VideoTypeBean.video_type_point, false, "POINT");
        public static final C4930e Tag_id = new C4930e(10, String.class, "tag_id", false, "TAG_ID");
        public static final C4930e Tag_names = new C4930e(11, String.class, "tag_names", false, "TAG_NAMES");
        public static final C4930e Link = new C4930e(12, String.class, "link", false, "LINK");
        public static final C4930e Canvas = new C4930e(13, String.class, "canvas", false, "CANVAS");
        public static final C4930e Video_path = new C4930e(14, String.class, "video_path", false, "VIDEO_PATH");
        public static final C4930e Image_path = new C4930e(15, String.class, "image_path", false, "IMAGE_PATH");
        public static final C4930e Time = new C4930e(16, Long.TYPE, "time", false, "TIME");
        public static final C4930e Is_draft = new C4930e(17, Boolean.TYPE, "is_draft", false, "IS_DRAFT");
        public static final C4930e Status = new C4930e(18, String.class, NotificationCompat.CATEGORY_STATUS, false, "STATUS");

        static {
            Class cls = Integer.TYPE;
            Total_slices = new C4930e(19, cls, "total_slices", false, "TOTAL_SLICES");
            Progress_slice = new C4930e(20, cls, "progress_slice", false, "PROGRESS_SLICE");
        }
    }

    public UploadBeanDao(C4942a c4942a, C0914d c0914d) {
        super(c4942a, c0914d);
    }

    @Override // p476m.p496b.p500b.AbstractC4926a
    /* renamed from: c */
    public Long mo4196c(UploadBean uploadBean) {
        UploadBean uploadBean2 = uploadBean;
        if (uploadBean2 != null) {
            return uploadBean2.getId();
        }
        return null;
    }

    @Override // p476m.p496b.p500b.AbstractC4926a
    /* renamed from: g */
    public UploadBean mo4197g(Cursor cursor, int i2) {
        int i3 = i2 + 0;
        Long valueOf = cursor.isNull(i3) ? null : Long.valueOf(cursor.getLong(i3));
        int i4 = i2 + 1;
        String string = cursor.isNull(i4) ? null : cursor.getString(i4);
        int i5 = i2 + 2;
        String string2 = cursor.isNull(i5) ? null : cursor.getString(i5);
        int i6 = i2 + 3;
        String string3 = cursor.isNull(i6) ? null : cursor.getString(i6);
        int i7 = i2 + 4;
        String string4 = cursor.isNull(i7) ? null : cursor.getString(i7);
        int i8 = i2 + 5;
        String string5 = cursor.isNull(i8) ? null : cursor.getString(i8);
        int i9 = i2 + 6;
        String string6 = cursor.isNull(i9) ? null : cursor.getString(i9);
        int i10 = i2 + 7;
        String string7 = cursor.isNull(i10) ? null : cursor.getString(i10);
        int i11 = i2 + 8;
        String string8 = cursor.isNull(i11) ? null : cursor.getString(i11);
        int i12 = i2 + 9;
        String string9 = cursor.isNull(i12) ? null : cursor.getString(i12);
        int i13 = i2 + 10;
        String string10 = cursor.isNull(i13) ? null : cursor.getString(i13);
        int i14 = i2 + 11;
        String string11 = cursor.isNull(i14) ? null : cursor.getString(i14);
        int i15 = i2 + 12;
        String string12 = cursor.isNull(i15) ? null : cursor.getString(i15);
        int i16 = i2 + 13;
        String string13 = cursor.isNull(i16) ? null : cursor.getString(i16);
        int i17 = i2 + 14;
        String string14 = cursor.isNull(i17) ? null : cursor.getString(i17);
        int i18 = i2 + 15;
        String string15 = cursor.isNull(i18) ? null : cursor.getString(i18);
        int i19 = i2 + 18;
        return new UploadBean(valueOf, string, string2, string3, string4, string5, string6, string7, string8, string9, string10, string11, string12, string13, string14, string15, cursor.getLong(i2 + 16), cursor.getShort(i2 + 17) != 0, cursor.isNull(i19) ? null : cursor.getString(i19), cursor.getInt(i2 + 19), cursor.getInt(i2 + 20));
    }

    @Override // p476m.p496b.p500b.AbstractC4926a
    /* renamed from: h */
    public Long mo4198h(Cursor cursor, int i2) {
        int i3 = i2 + 0;
        if (cursor.isNull(i3)) {
            return null;
        }
        return Long.valueOf(cursor.getLong(i3));
    }
}
