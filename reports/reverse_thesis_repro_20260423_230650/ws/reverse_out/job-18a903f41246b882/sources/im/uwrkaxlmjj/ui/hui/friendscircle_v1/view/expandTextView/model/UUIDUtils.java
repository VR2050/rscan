package im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.expandTextView.model;

import androidx.exifinterface.media.ExifInterface;
import com.google.android.exoplayer2.text.ttml.TtmlNode;
import im.uwrkaxlmjj.messenger.ImageLoader;
import java.util.UUID;

/* JADX INFO: loaded from: classes5.dex */
public class UUIDUtils {
    public static String[] chars = {"a", "b", "c", "d", "e", "f", ImageLoader.AUTOPLAY_FILTER, "h", "i", "j", "k", "l", "m", "n", "o", TtmlNode.TAG_P, "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "0", "1", "2", ExifInterface.GPS_MEASUREMENT_3D, "4", "5", "6", "7", "8", "9", ExifInterface.GPS_MEASUREMENT_IN_PROGRESS, "B", "C", "D", ExifInterface.LONGITUDE_EAST, "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", ExifInterface.LATITUDE_SOUTH, ExifInterface.GPS_DIRECTION_TRUE, "U", ExifInterface.GPS_MEASUREMENT_INTERRUPTED, ExifInterface.LONGITUDE_WEST, "X", "Y", "Z"};

    public static String getUuid() {
        return UUID.randomUUID().toString().replaceAll("-", "");
    }

    public static String getUuid(int length) {
        StringBuilder stringBuilder = new StringBuilder(UUID.randomUUID().toString());
        while (stringBuilder.length() < length) {
            stringBuilder.append(UUID.randomUUID().toString());
        }
        return stringBuilder.substring(0, length);
    }
}
