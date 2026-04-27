package im.uwrkaxlmjj.messenger;

import android.content.SharedPreferences;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Paint;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.text.style.ImageSpan;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import com.google.android.exoplayer2.text.ttml.TtmlNode;
import java.io.File;
import java.io.InputStream;
import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/* JADX INFO: loaded from: classes2.dex */
public class Emoji {
    private static final int MAX_RECENT_EMOJI_COUNT = 48;
    private static int bigImgSize = 0;
    private static int drawImgSize = 0;
    private static Paint placeholderPaint = null;
    private static boolean recentEmojiLoaded = false;
    private static final int splitCount = 4;
    private static HashMap<CharSequence, DrawableInfo> rects = new HashMap<>();
    private static boolean inited = false;
    private static Bitmap[][] emojiBmp = (Bitmap[][]) Array.newInstance((Class<?>) Bitmap.class, 8, 4);
    private static boolean[][] loadingEmoji = (boolean[][]) Array.newInstance((Class<?>) boolean.class, 8, 4);
    public static HashMap<String, Integer> emojiUseHistory = new HashMap<>();
    public static ArrayList<String> recentEmoji = new ArrayList<>();
    public static HashMap<String, String> emojiColor = new HashMap<>();
    private static final int[][] cols = {new int[]{16, 16, 16, 16}, new int[]{6, 6, 6, 6}, new int[]{5, 5, 5, 5}, new int[]{7, 7, 7, 7}, new int[]{5, 5, 5, 5}, new int[]{7, 7, 7, 7}, new int[]{8, 8, 8, 8}, new int[]{8, 8, 8, 8}};

    static {
        int emojiFullSize;
        int add = 2;
        if (AndroidUtilities.density <= 1.0f) {
            emojiFullSize = 33;
            add = 1;
        } else if (AndroidUtilities.density > 1.5f && AndroidUtilities.density <= 2.0f) {
            emojiFullSize = 66;
        } else {
            emojiFullSize = 66;
        }
        drawImgSize = AndroidUtilities.dp(20.0f);
        bigImgSize = AndroidUtilities.dp(AndroidUtilities.isTablet() ? 40.0f : 34.0f);
        for (int j = 0; j < EmojiData.data.length; j++) {
            int count2 = (int) Math.ceil(EmojiData.data[j].length / 4.0f);
            for (int i = 0; i < EmojiData.data[j].length; i++) {
                int page = i / count2;
                int position = i - (page * count2);
                int[][] iArr = cols;
                int row = position % iArr[j][page];
                int col = position / iArr[j][page];
                Rect rect = new Rect((row * emojiFullSize) + (row * add), (col * emojiFullSize) + (col * add), ((row + 1) * emojiFullSize) + (row * add), ((col + 1) * emojiFullSize) + (col * add));
                rects.put(EmojiData.data[j][i], new DrawableInfo(rect, (byte) j, (byte) page, i));
            }
        }
        Paint paint = new Paint();
        placeholderPaint = paint;
        paint.setColor(0);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void loadEmoji(final int page, final int page2) {
        float scale;
        int imageResize = 1;
        try {
            if (AndroidUtilities.density <= 1.0f) {
                scale = 2.0f;
                imageResize = 2;
            } else {
                float scale2 = AndroidUtilities.density;
                if (scale2 <= 1.5f) {
                    scale = 2.0f;
                } else {
                    float scale3 = AndroidUtilities.density;
                    if (scale3 <= 2.0f) {
                        scale = 2.0f;
                    } else {
                        scale = 2.0f;
                    }
                }
            }
            for (int a = 12; a < 14; a++) {
                try {
                    String imageName = String.format(Locale.US, "v%d_emoji%.01fx_%d.png", Integer.valueOf(a), Float.valueOf(scale), Integer.valueOf(page));
                    File imageFile = ApplicationLoader.applicationContext.getFileStreamPath(imageName);
                    if (imageFile.exists()) {
                        imageFile.delete();
                    }
                } catch (Exception e) {
                    FileLog.e(e);
                    Bitmap bitmap = null;
                    InputStream is = ApplicationLoader.applicationContext.getAssets().open("emoji/" + String.format(Locale.US, "v14_emoji%.01fx_%d_%d.png", Float.valueOf(scale), Integer.valueOf(page), Integer.valueOf(page2)));
                    BitmapFactory.Options opts = new BitmapFactory.Options();
                    opts.inJustDecodeBounds = false;
                    opts.inSampleSize = imageResize;
                    int i = Build.VERSION.SDK_INT;
                    bitmap = BitmapFactory.decodeStream(is, null, opts);
                    is.close();
                    final Bitmap finalBitmap = bitmap;
                    AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$Emoji$GIj6JacMRbPjTTDTfXdA7X4H4Zk
                        @Override // java.lang.Runnable
                        public final void run() {
                            Emoji.lambda$loadEmoji$0(page, page2, finalBitmap);
                        }
                    });
                }
            }
            Bitmap bitmap2 = null;
            try {
                InputStream is2 = ApplicationLoader.applicationContext.getAssets().open("emoji/" + String.format(Locale.US, "v14_emoji%.01fx_%d_%d.png", Float.valueOf(scale), Integer.valueOf(page), Integer.valueOf(page2)));
                BitmapFactory.Options opts2 = new BitmapFactory.Options();
                opts2.inJustDecodeBounds = false;
                opts2.inSampleSize = imageResize;
                int i2 = Build.VERSION.SDK_INT;
                bitmap2 = BitmapFactory.decodeStream(is2, null, opts2);
                is2.close();
            } catch (Throwable e2) {
                FileLog.e(e2);
            }
            final Bitmap finalBitmap2 = bitmap2;
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$Emoji$GIj6JacMRbPjTTDTfXdA7X4H4Zk
                @Override // java.lang.Runnable
                public final void run() {
                    Emoji.lambda$loadEmoji$0(page, page2, finalBitmap2);
                }
            });
        } catch (Throwable x) {
            if (BuildVars.LOGS_ENABLED) {
                FileLog.e("Error loading emoji", x);
            }
        }
    }

    static /* synthetic */ void lambda$loadEmoji$0(int page, int page2, Bitmap finalBitmap) {
        emojiBmp[page][page2] = finalBitmap;
        NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.emojiDidLoad, new Object[0]);
    }

    public static void invalidateAll(View view) {
        if (view instanceof ViewGroup) {
            ViewGroup g = (ViewGroup) view;
            for (int i = 0; i < g.getChildCount(); i++) {
                invalidateAll(g.getChildAt(i));
            }
            return;
        }
        if (view instanceof TextView) {
            view.invalidate();
        }
    }

    public static String fixEmoji(String emoji) {
        int length = emoji.length();
        int a = 0;
        while (a < length) {
            char ch = emoji.charAt(a);
            if (ch >= 55356 && ch <= 55358) {
                if (ch == 55356 && a < length - 1) {
                    char ch2 = emoji.charAt(a + 1);
                    if (ch2 == 56879 || ch2 == 56324 || ch2 == 56858 || ch2 == 56703) {
                        emoji = emoji.substring(0, a + 2) + "️" + emoji.substring(a + 2);
                        length++;
                        a += 2;
                    } else {
                        a++;
                    }
                } else {
                    a++;
                }
            } else {
                if (ch == 8419) {
                    return emoji;
                }
                if (ch >= 8252 && ch <= 12953 && EmojiData.emojiToFE0FMap.containsKey(Character.valueOf(ch))) {
                    emoji = emoji.substring(0, a + 1) + "️" + emoji.substring(a + 1);
                    length++;
                    a++;
                }
            }
            a++;
        }
        return emoji;
    }

    public static EmojiDrawable getEmojiDrawable(CharSequence code) {
        CharSequence newCode;
        DrawableInfo info = rects.get(code);
        if (info == null && (newCode = EmojiData.emojiAliasMap.get(code)) != null) {
            info = rects.get(newCode);
        }
        if (info == null) {
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d("No drawable for emoji " + ((Object) code));
                return null;
            }
            return null;
        }
        EmojiDrawable ed = new EmojiDrawable(info);
        int i = drawImgSize;
        ed.setBounds(0, 0, i, i);
        return ed;
    }

    public static boolean isValidEmoji(CharSequence code) {
        CharSequence newCode;
        DrawableInfo info = rects.get(code);
        if (info == null && (newCode = EmojiData.emojiAliasMap.get(code)) != null) {
            info = rects.get(newCode);
        }
        return info != null;
    }

    public static Drawable getEmojiBigDrawable(String code) {
        CharSequence newCode;
        EmojiDrawable ed = getEmojiDrawable(code);
        if (ed == null && (newCode = EmojiData.emojiAliasMap.get(code)) != null) {
            ed = getEmojiDrawable(newCode);
        }
        if (ed == null) {
            return null;
        }
        int i = bigImgSize;
        ed.setBounds(0, 0, i, i);
        ed.fullSize = true;
        return ed;
    }

    public static class EmojiDrawable extends Drawable {
        private static Paint paint = new Paint(2);
        private static Rect rect = new Rect();
        private boolean fullSize = false;
        private DrawableInfo info;

        public EmojiDrawable(DrawableInfo i) {
            this.info = i;
        }

        public DrawableInfo getDrawableInfo() {
            return this.info;
        }

        public Rect getDrawRect() {
            Rect original = getBounds();
            int cX = original.centerX();
            int cY = original.centerY();
            rect.left = cX - ((this.fullSize ? Emoji.bigImgSize : Emoji.drawImgSize) / 2);
            rect.right = ((this.fullSize ? Emoji.bigImgSize : Emoji.drawImgSize) / 2) + cX;
            rect.top = cY - ((this.fullSize ? Emoji.bigImgSize : Emoji.drawImgSize) / 2);
            rect.bottom = ((this.fullSize ? Emoji.bigImgSize : Emoji.drawImgSize) / 2) + cY;
            return rect;
        }

        @Override // android.graphics.drawable.Drawable
        public void draw(Canvas canvas) {
            Rect b;
            if (Emoji.emojiBmp[this.info.page][this.info.page2] == null) {
                if (!Emoji.loadingEmoji[this.info.page][this.info.page2]) {
                    Emoji.loadingEmoji[this.info.page][this.info.page2] = true;
                    Utilities.globalQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$Emoji$EmojiDrawable$nVA0zvjGiTewzVDTvGPTZDq1POQ
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$draw$0$Emoji$EmojiDrawable();
                        }
                    });
                    canvas.drawRect(getBounds(), Emoji.placeholderPaint);
                    return;
                }
                return;
            }
            if (this.fullSize) {
                b = getDrawRect();
            } else {
                b = getBounds();
            }
            canvas.drawBitmap(Emoji.emojiBmp[this.info.page][this.info.page2], this.info.rect, b, paint);
        }

        public /* synthetic */ void lambda$draw$0$Emoji$EmojiDrawable() {
            Emoji.loadEmoji(this.info.page, this.info.page2);
            Emoji.loadingEmoji[this.info.page][this.info.page2] = false;
        }

        @Override // android.graphics.drawable.Drawable
        public int getOpacity() {
            return -2;
        }

        @Override // android.graphics.drawable.Drawable
        public void setAlpha(int alpha) {
        }

        @Override // android.graphics.drawable.Drawable
        public void setColorFilter(ColorFilter cf) {
        }
    }

    private static class DrawableInfo {
        public int emojiIndex;
        public byte page;
        public byte page2;
        public Rect rect;

        public DrawableInfo(Rect r, byte p, byte p2, int index) {
            this.rect = r;
            this.page = p;
            this.page2 = p2;
            this.emojiIndex = index;
        }
    }

    private static boolean inArray(char c, char[] a) {
        for (char cc : a) {
            if (cc == c) {
                return true;
            }
        }
        return false;
    }

    public static CharSequence replaceEmoji(CharSequence cs, Paint.FontMetricsInt fontMetrics, int size, boolean createNew) {
        return replaceEmoji(cs, fontMetrics, size, createNew, null);
    }

    /* JADX WARN: Removed duplicated region for block: B:121:0x01c4  */
    /* JADX WARN: Removed duplicated region for block: B:125:0x01ce A[Catch: Exception -> 0x0221, TryCatch #7 {Exception -> 0x0221, blocks: (B:99:0x015e, B:103:0x016c, B:125:0x01ce, B:127:0x01d2, B:131:0x01e0, B:133:0x01e6, B:156:0x0229, B:151:0x0218, B:158:0x022e, B:160:0x0232, B:162:0x023d, B:166:0x024d, B:171:0x0268, B:104:0x017c, B:106:0x0183, B:108:0x018d, B:112:0x019c, B:113:0x019e, B:115:0x01b1, B:117:0x01b7), top: B:216:0x015e }] */
    /* JADX WARN: Removed duplicated region for block: B:170:0x0266  */
    /* JADX WARN: Removed duplicated region for block: B:181:0x02b0  */
    /* JADX WARN: Removed duplicated region for block: B:92:0x0149  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.lang.CharSequence replaceEmoji(java.lang.CharSequence r30, android.graphics.Paint.FontMetricsInt r31, int r32, boolean r33, int[] r34) {
        /*
            Method dump skipped, instruction units count: 754
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.Emoji.replaceEmoji(java.lang.CharSequence, android.graphics.Paint$FontMetricsInt, int, boolean, int[]):java.lang.CharSequence");
    }

    public static class EmojiSpan extends ImageSpan {
        private Paint.FontMetricsInt fontMetrics;
        private int size;

        public EmojiSpan(EmojiDrawable d, int verticalAlignment, int s, Paint.FontMetricsInt original) {
            super(d, verticalAlignment);
            this.size = AndroidUtilities.dp(20.0f);
            this.fontMetrics = original;
            if (original != null) {
                int iAbs = Math.abs(original.descent) + Math.abs(this.fontMetrics.ascent);
                this.size = iAbs;
                if (iAbs == 0) {
                    this.size = AndroidUtilities.dp(20.0f);
                }
            }
        }

        public void replaceFontMetrics(Paint.FontMetricsInt newMetrics, int newSize) {
            this.fontMetrics = newMetrics;
            this.size = newSize;
        }

        @Override // android.text.style.DynamicDrawableSpan, android.text.style.ReplacementSpan
        public int getSize(Paint paint, CharSequence text, int start, int end, Paint.FontMetricsInt fm) {
            if (fm == null) {
                fm = new Paint.FontMetricsInt();
            }
            Paint.FontMetricsInt fontMetricsInt = this.fontMetrics;
            if (fontMetricsInt == null) {
                int sz = super.getSize(paint, text, start, end, fm);
                int offset = AndroidUtilities.dp(8.0f);
                int w = AndroidUtilities.dp(10.0f);
                fm.top = (-w) - offset;
                fm.bottom = w - offset;
                fm.ascent = (-w) - offset;
                fm.leading = 0;
                fm.descent = w - offset;
                return sz;
            }
            if (fm != null) {
                fm.ascent = fontMetricsInt.ascent;
                fm.descent = this.fontMetrics.descent;
                fm.top = this.fontMetrics.top;
                fm.bottom = this.fontMetrics.bottom;
            }
            if (getDrawable() != null) {
                Drawable drawable = getDrawable();
                int i = this.size;
                drawable.setBounds(0, 0, i, i);
            }
            return this.size;
        }
    }

    public static void addRecentEmoji(String code) {
        Integer count = emojiUseHistory.get(code);
        if (count == null) {
            count = 0;
        }
        if (count.intValue() == 0 && emojiUseHistory.size() >= 48) {
            String emoji = recentEmoji.get(r1.size() - 1);
            emojiUseHistory.remove(emoji);
            recentEmoji.set(r2.size() - 1, code);
        }
        emojiUseHistory.put(code, Integer.valueOf(count.intValue() + 1));
    }

    public static void sortEmoji() {
        recentEmoji.clear();
        for (Map.Entry<String, Integer> entry : emojiUseHistory.entrySet()) {
            recentEmoji.add(entry.getKey());
        }
        Collections.sort(recentEmoji, new Comparator() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$Emoji$R4l6GX3WCCc_1R1Crkc7uSswxoU
            @Override // java.util.Comparator
            public final int compare(Object obj, Object obj2) {
                return Emoji.lambda$sortEmoji$1((String) obj, (String) obj2);
            }
        });
        while (recentEmoji.size() > 48) {
            recentEmoji.remove(r0.size() - 1);
        }
    }

    static /* synthetic */ int lambda$sortEmoji$1(String lhs, String rhs) {
        Integer count1 = emojiUseHistory.get(lhs);
        Integer count2 = emojiUseHistory.get(rhs);
        if (count1 == null) {
            count1 = 0;
        }
        if (count2 == null) {
            count2 = 0;
        }
        if (count1.intValue() > count2.intValue()) {
            return -1;
        }
        if (count1.intValue() >= count2.intValue()) {
            return 0;
        }
        return 1;
    }

    public static void saveRecentEmoji() {
        SharedPreferences preferences = MessagesController.getGlobalEmojiSettings();
        StringBuilder stringBuilder = new StringBuilder();
        for (Map.Entry<String, Integer> entry : emojiUseHistory.entrySet()) {
            if (stringBuilder.length() != 0) {
                stringBuilder.append(",");
            }
            stringBuilder.append(entry.getKey());
            stringBuilder.append("=");
            stringBuilder.append(entry.getValue());
        }
        preferences.edit().putString("emojis2", stringBuilder.toString()).commit();
    }

    public static void clearRecentEmoji() {
        SharedPreferences preferences = MessagesController.getGlobalEmojiSettings();
        preferences.edit().putBoolean("filled_default", true).commit();
        emojiUseHistory.clear();
        recentEmoji.clear();
        saveRecentEmoji();
    }

    public static void loadRecentEmoji() {
        String str;
        String str2;
        StringBuilder string;
        String[] args;
        if (recentEmojiLoaded) {
            return;
        }
        recentEmojiLoaded = true;
        SharedPreferences preferences = MessagesController.getGlobalEmojiSettings();
        char c = 0;
        try {
            emojiUseHistory.clear();
            if (preferences.contains("emojis")) {
                String str3 = preferences.getString("emojis", "");
                if (str3 == null || str3.length() <= 0) {
                    str = str3;
                } else {
                    String[] args2 = str3.split(",");
                    int length = args2.length;
                    int i = 0;
                    while (i < length) {
                        String arg = args2[i];
                        String[] args22 = arg.split("=");
                        long value = Utilities.parseLong(args22[c]).longValue();
                        StringBuilder string2 = new StringBuilder();
                        int a = 0;
                        while (true) {
                            if (a >= 4) {
                                str2 = str3;
                                string = string2;
                                args = args2;
                                break;
                            }
                            char ch = (char) value;
                            str2 = str3;
                            string = string2;
                            args = args2;
                            string.insert(0, ch);
                            value >>= 16;
                            if (value == 0) {
                                break;
                            }
                            a++;
                            args2 = args;
                            string2 = string;
                            str3 = str2;
                        }
                        int a2 = string.length();
                        if (a2 > 0) {
                            emojiUseHistory.put(string.toString(), Utilities.parseInt(args22[1]));
                        }
                        i++;
                        args2 = args;
                        str3 = str2;
                        c = 0;
                    }
                    str = str3;
                }
                preferences.edit().remove("emojis").commit();
                saveRecentEmoji();
            } else {
                String str4 = preferences.getString("emojis2", "");
                if (str4 != null && str4.length() > 0) {
                    String[] args3 = str4.split(",");
                    for (String arg2 : args3) {
                        String[] args23 = arg2.split("=");
                        emojiUseHistory.put(args23[0], Utilities.parseInt(args23[1]));
                    }
                }
            }
            if (emojiUseHistory.isEmpty() && !preferences.getBoolean("filled_default", false)) {
                String[] newRecent = {"😂", "😘", "❤", "😍", "😊", "😁", "👍", "☺", "😔", "😄", "😭", "💋", "😒", "😳", "😜", "🙈", "😉", "😃", "😢", "😝", "😱", "😡", "😏", "😞", "😅", "😚", "🙊", "😌", "😀", "😋", "😆", "👌", "😐", "😕"};
                for (int i2 = 0; i2 < newRecent.length; i2++) {
                    emojiUseHistory.put(newRecent[i2], Integer.valueOf(newRecent.length - i2));
                }
                preferences.edit().putBoolean("filled_default", true).commit();
                saveRecentEmoji();
            }
            sortEmoji();
        } catch (Exception e) {
            FileLog.e(e);
        }
        try {
            String str5 = preferences.getString(TtmlNode.ATTR_TTS_COLOR, "");
            if (str5 != null && str5.length() > 0) {
                String[] args4 = str5.split(",");
                for (String arg3 : args4) {
                    String[] args24 = arg3.split("=");
                    emojiColor.put(args24[0], args24[1]);
                }
            }
        } catch (Exception e2) {
            FileLog.e(e2);
        }
    }

    public static void saveEmojiColors() {
        SharedPreferences preferences = MessagesController.getGlobalEmojiSettings();
        StringBuilder stringBuilder = new StringBuilder();
        for (Map.Entry<String, String> entry : emojiColor.entrySet()) {
            if (stringBuilder.length() != 0) {
                stringBuilder.append(",");
            }
            stringBuilder.append(entry.getKey());
            stringBuilder.append("=");
            stringBuilder.append(entry.getValue());
        }
        preferences.edit().putString(TtmlNode.ATTR_TTS_COLOR, stringBuilder.toString()).commit();
    }
}
