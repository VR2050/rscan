package androidx.camera.core.impl.utils;

import android.location.Location;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.camera.core.Logger;
import androidx.exifinterface.media.ExifInterface;
import com.google.android.material.shadow.ShadowDrawableWrapper;
import com.luck.picture.lib.widget.longimage.SubsamplingScaleImageView;
import java.io.File;
import java.io.InputStream;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public final class Exif {
    public static final long INVALID_TIMESTAMP = -1;
    private static final String KILOMETERS_PER_HOUR = "K";
    private static final String KNOTS = "N";
    private static final String MILES_PER_HOUR = "M";
    private static final String TAG = "Exif";
    private final ExifInterface mExifInterface;
    private boolean mRemoveTimestamp = false;
    private static final ThreadLocal<SimpleDateFormat> DATE_FORMAT = new ThreadLocal<SimpleDateFormat>() { // from class: androidx.camera.core.impl.utils.Exif.1
        @Override // java.lang.ThreadLocal
        public SimpleDateFormat initialValue() {
            return new SimpleDateFormat("yyyy:MM:dd", Locale.US);
        }
    };
    private static final ThreadLocal<SimpleDateFormat> TIME_FORMAT = new ThreadLocal<SimpleDateFormat>() { // from class: androidx.camera.core.impl.utils.Exif.2
        @Override // java.lang.ThreadLocal
        public SimpleDateFormat initialValue() {
            return new SimpleDateFormat("HH:mm:ss", Locale.US);
        }
    };
    private static final ThreadLocal<SimpleDateFormat> DATETIME_FORMAT = new ThreadLocal<SimpleDateFormat>() { // from class: androidx.camera.core.impl.utils.Exif.3
        @Override // java.lang.ThreadLocal
        public SimpleDateFormat initialValue() {
            return new SimpleDateFormat("yyyy:MM:dd HH:mm:ss", Locale.US);
        }
    };

    public static final class Speed {

        public static final class Converter {
            public final double mMph;

            public Converter(double d2) {
                this.mMph = d2;
            }

            public double toKilometersPerHour() {
                return this.mMph / 0.621371d;
            }

            public double toKnots() {
                return this.mMph / 1.15078d;
            }

            public double toMetersPerSecond() {
                return this.mMph / 2.23694d;
            }

            public double toMilesPerHour() {
                return this.mMph;
            }
        }

        private Speed() {
        }

        public static Converter fromKilometersPerHour(double d2) {
            return new Converter(d2 * 0.621371d);
        }

        public static Converter fromKnots(double d2) {
            return new Converter(d2 * 1.15078d);
        }

        public static Converter fromMetersPerSecond(double d2) {
            return new Converter(d2 * 2.23694d);
        }

        public static Converter fromMilesPerHour(double d2) {
            return new Converter(d2);
        }
    }

    private Exif(ExifInterface exifInterface) {
        this.mExifInterface = exifInterface;
    }

    private void attachLastModifiedTimestamp() {
        long currentTimeMillis = System.currentTimeMillis();
        String convertToExifDateTime = convertToExifDateTime(currentTimeMillis);
        this.mExifInterface.setAttribute(ExifInterface.TAG_DATETIME, convertToExifDateTime);
        try {
            this.mExifInterface.setAttribute(ExifInterface.TAG_SUBSEC_TIME, Long.toString(currentTimeMillis - convertFromExifDateTime(convertToExifDateTime).getTime()));
        } catch (ParseException unused) {
        }
    }

    private static Date convertFromExifDate(String str) {
        return DATE_FORMAT.get().parse(str);
    }

    private static Date convertFromExifDateTime(String str) {
        return DATETIME_FORMAT.get().parse(str);
    }

    private static Date convertFromExifTime(String str) {
        return TIME_FORMAT.get().parse(str);
    }

    private static String convertToExifDateTime(long j2) {
        return DATETIME_FORMAT.get().format(new Date(j2));
    }

    @NonNull
    public static Exif createFromFile(@NonNull File file) {
        return createFromFileString(file.toString());
    }

    @NonNull
    public static Exif createFromFileString(@NonNull String str) {
        return new Exif(new ExifInterface(str));
    }

    @NonNull
    public static Exif createFromInputStream(@NonNull InputStream inputStream) {
        return new Exif(new ExifInterface(inputStream));
    }

    private long parseTimestamp(@Nullable String str, @Nullable String str2) {
        if (str == null && str2 == null) {
            return -1L;
        }
        if (str2 == null) {
            try {
                return convertFromExifDate(str).getTime();
            } catch (ParseException unused) {
                return -1L;
            }
        }
        if (str != null) {
            return parseTimestamp(C1499a.m639y(str, " ", str2));
        }
        try {
            return convertFromExifTime(str2).getTime();
        } catch (ParseException unused2) {
            return -1L;
        }
    }

    public void attachLocation(@NonNull Location location) {
        this.mExifInterface.setGpsInfo(location);
    }

    public void attachTimestamp() {
        long currentTimeMillis = System.currentTimeMillis();
        String convertToExifDateTime = convertToExifDateTime(currentTimeMillis);
        this.mExifInterface.setAttribute(ExifInterface.TAG_DATETIME_ORIGINAL, convertToExifDateTime);
        this.mExifInterface.setAttribute(ExifInterface.TAG_DATETIME_DIGITIZED, convertToExifDateTime);
        try {
            String l2 = Long.toString(currentTimeMillis - convertFromExifDateTime(convertToExifDateTime).getTime());
            this.mExifInterface.setAttribute(ExifInterface.TAG_SUBSEC_TIME_ORIGINAL, l2);
            this.mExifInterface.setAttribute(ExifInterface.TAG_SUBSEC_TIME_DIGITIZED, l2);
        } catch (ParseException unused) {
        }
        this.mRemoveTimestamp = false;
    }

    public void flipHorizontally() {
        int i2;
        switch (getOrientation()) {
            case 2:
                i2 = 1;
                break;
            case 3:
                i2 = 4;
                break;
            case 4:
                i2 = 3;
                break;
            case 5:
                i2 = 6;
                break;
            case 6:
                i2 = 5;
                break;
            case 7:
                i2 = 8;
                break;
            case 8:
                i2 = 7;
                break;
            default:
                i2 = 2;
                break;
        }
        this.mExifInterface.setAttribute(ExifInterface.TAG_ORIENTATION, String.valueOf(i2));
    }

    public void flipVertically() {
        int i2;
        switch (getOrientation()) {
            case 2:
                i2 = 3;
                break;
            case 3:
                i2 = 2;
                break;
            case 4:
                i2 = 1;
                break;
            case 5:
                i2 = 8;
                break;
            case 6:
                i2 = 7;
                break;
            case 7:
                i2 = 6;
                break;
            case 8:
                i2 = 5;
                break;
            default:
                i2 = 4;
                break;
        }
        this.mExifInterface.setAttribute(ExifInterface.TAG_ORIENTATION, String.valueOf(i2));
    }

    @Nullable
    public String getDescription() {
        return this.mExifInterface.getAttribute(ExifInterface.TAG_IMAGE_DESCRIPTION);
    }

    public int getHeight() {
        return this.mExifInterface.getAttributeInt(ExifInterface.TAG_IMAGE_LENGTH, 0);
    }

    public long getLastModifiedTimestamp() {
        long parseTimestamp = parseTimestamp(this.mExifInterface.getAttribute(ExifInterface.TAG_DATETIME));
        if (parseTimestamp == -1) {
            return -1L;
        }
        String attribute = this.mExifInterface.getAttribute(ExifInterface.TAG_SUBSEC_TIME);
        if (attribute == null) {
            return parseTimestamp;
        }
        try {
            long parseLong = Long.parseLong(attribute);
            while (parseLong > 1000) {
                parseLong /= 10;
            }
            return parseTimestamp + parseLong;
        } catch (NumberFormatException unused) {
            return parseTimestamp;
        }
    }

    @Nullable
    public Location getLocation() {
        String attribute = this.mExifInterface.getAttribute(ExifInterface.TAG_GPS_PROCESSING_METHOD);
        double[] latLong = this.mExifInterface.getLatLong();
        double altitude = this.mExifInterface.getAltitude(ShadowDrawableWrapper.COS_45);
        double attributeDouble = this.mExifInterface.getAttributeDouble(ExifInterface.TAG_GPS_SPEED, ShadowDrawableWrapper.COS_45);
        String attribute2 = this.mExifInterface.getAttribute(ExifInterface.TAG_GPS_SPEED_REF);
        if (attribute2 == null) {
            attribute2 = "K";
        }
        long parseTimestamp = parseTimestamp(this.mExifInterface.getAttribute(ExifInterface.TAG_GPS_DATESTAMP), this.mExifInterface.getAttribute(ExifInterface.TAG_GPS_TIMESTAMP));
        if (latLong == null) {
            return null;
        }
        if (attribute == null) {
            attribute = TAG;
        }
        Location location = new Location(attribute);
        location.setLatitude(latLong[0]);
        location.setLongitude(latLong[1]);
        if (altitude != ShadowDrawableWrapper.COS_45) {
            location.setAltitude(altitude);
        }
        if (attributeDouble != ShadowDrawableWrapper.COS_45) {
            char c2 = 65535;
            int hashCode = attribute2.hashCode();
            if (hashCode != 75) {
                if (hashCode != 77) {
                    if (hashCode == 78 && attribute2.equals("N")) {
                        c2 = 1;
                    }
                } else if (attribute2.equals("M")) {
                    c2 = 0;
                }
            } else if (attribute2.equals("K")) {
                c2 = 2;
            }
            location.setSpeed((float) (c2 != 0 ? c2 != 1 ? Speed.fromKilometersPerHour(attributeDouble).toMetersPerSecond() : Speed.fromKnots(attributeDouble).toMetersPerSecond() : Speed.fromMilesPerHour(attributeDouble).toMetersPerSecond()));
        }
        if (parseTimestamp != -1) {
            location.setTime(parseTimestamp);
        }
        return location;
    }

    public int getOrientation() {
        return this.mExifInterface.getAttributeInt(ExifInterface.TAG_ORIENTATION, 0);
    }

    public int getRotation() {
        switch (getOrientation()) {
            case 3:
            case 4:
                return 180;
            case 5:
                return SubsamplingScaleImageView.ORIENTATION_270;
            case 6:
            case 7:
                return 90;
            case 8:
                return SubsamplingScaleImageView.ORIENTATION_270;
            default:
                return 0;
        }
    }

    public long getTimestamp() {
        long parseTimestamp = parseTimestamp(this.mExifInterface.getAttribute(ExifInterface.TAG_DATETIME_ORIGINAL));
        if (parseTimestamp == -1) {
            return -1L;
        }
        String attribute = this.mExifInterface.getAttribute(ExifInterface.TAG_SUBSEC_TIME_ORIGINAL);
        if (attribute == null) {
            return parseTimestamp;
        }
        try {
            long parseLong = Long.parseLong(attribute);
            while (parseLong > 1000) {
                parseLong /= 10;
            }
            return parseTimestamp + parseLong;
        } catch (NumberFormatException unused) {
            return parseTimestamp;
        }
    }

    public int getWidth() {
        return this.mExifInterface.getAttributeInt(ExifInterface.TAG_IMAGE_WIDTH, 0);
    }

    public boolean isFlippedHorizontally() {
        return getOrientation() == 2;
    }

    public boolean isFlippedVertically() {
        int orientation = getOrientation();
        return orientation == 4 || orientation == 5 || orientation == 7;
    }

    public void removeLocation() {
        this.mExifInterface.setAttribute(ExifInterface.TAG_GPS_PROCESSING_METHOD, null);
        this.mExifInterface.setAttribute(ExifInterface.TAG_GPS_LATITUDE, null);
        this.mExifInterface.setAttribute(ExifInterface.TAG_GPS_LATITUDE_REF, null);
        this.mExifInterface.setAttribute(ExifInterface.TAG_GPS_LONGITUDE, null);
        this.mExifInterface.setAttribute(ExifInterface.TAG_GPS_LONGITUDE_REF, null);
        this.mExifInterface.setAttribute(ExifInterface.TAG_GPS_ALTITUDE, null);
        this.mExifInterface.setAttribute(ExifInterface.TAG_GPS_ALTITUDE_REF, null);
        this.mExifInterface.setAttribute(ExifInterface.TAG_GPS_SPEED, null);
        this.mExifInterface.setAttribute(ExifInterface.TAG_GPS_SPEED_REF, null);
        this.mExifInterface.setAttribute(ExifInterface.TAG_GPS_DATESTAMP, null);
        this.mExifInterface.setAttribute(ExifInterface.TAG_GPS_TIMESTAMP, null);
    }

    public void removeTimestamp() {
        this.mExifInterface.setAttribute(ExifInterface.TAG_DATETIME, null);
        this.mExifInterface.setAttribute(ExifInterface.TAG_DATETIME_ORIGINAL, null);
        this.mExifInterface.setAttribute(ExifInterface.TAG_DATETIME_DIGITIZED, null);
        this.mExifInterface.setAttribute(ExifInterface.TAG_SUBSEC_TIME, null);
        this.mExifInterface.setAttribute(ExifInterface.TAG_SUBSEC_TIME_ORIGINAL, null);
        this.mExifInterface.setAttribute(ExifInterface.TAG_SUBSEC_TIME_DIGITIZED, null);
        this.mRemoveTimestamp = true;
    }

    public void rotate(int i2) {
        if (i2 % 90 != 0) {
            Logger.m129w(TAG, String.format(Locale.US, "Can only rotate in right angles (eg. 0, 90, 180, 270). %d is unsupported.", Integer.valueOf(i2)));
            this.mExifInterface.setAttribute(ExifInterface.TAG_ORIENTATION, String.valueOf(0));
            return;
        }
        int i3 = i2 % 360;
        int orientation = getOrientation();
        while (i3 < 0) {
            i3 += 90;
            switch (orientation) {
                case 2:
                    orientation = 5;
                    break;
                case 3:
                case 8:
                    orientation = 6;
                    break;
                case 4:
                    orientation = 7;
                    break;
                case 5:
                    orientation = 4;
                    break;
                case 6:
                    orientation = 1;
                    break;
                case 7:
                    orientation = 2;
                    break;
                default:
                    orientation = 8;
                    break;
            }
        }
        while (i3 > 0) {
            i3 -= 90;
            switch (orientation) {
                case 2:
                    orientation = 7;
                    break;
                case 3:
                    orientation = 8;
                    break;
                case 4:
                    orientation = 5;
                    break;
                case 5:
                    orientation = 2;
                    break;
                case 6:
                    orientation = 3;
                    break;
                case 7:
                    orientation = 4;
                    break;
                case 8:
                    orientation = 1;
                    break;
                default:
                    orientation = 6;
                    break;
            }
        }
        this.mExifInterface.setAttribute(ExifInterface.TAG_ORIENTATION, String.valueOf(orientation));
    }

    public void save() {
        if (!this.mRemoveTimestamp) {
            attachLastModifiedTimestamp();
        }
        this.mExifInterface.saveAttributes();
    }

    public void setDescription(@Nullable String str) {
        this.mExifInterface.setAttribute(ExifInterface.TAG_IMAGE_DESCRIPTION, str);
    }

    public void setOrientation(int i2) {
        this.mExifInterface.setAttribute(ExifInterface.TAG_ORIENTATION, String.valueOf(i2));
    }

    public String toString() {
        return String.format(Locale.ENGLISH, "Exif{width=%s, height=%s, rotation=%d, isFlippedVertically=%s, isFlippedHorizontally=%s, location=%s, timestamp=%s, description=%s}", Integer.valueOf(getWidth()), Integer.valueOf(getHeight()), Integer.valueOf(getRotation()), Boolean.valueOf(isFlippedVertically()), Boolean.valueOf(isFlippedHorizontally()), getLocation(), Long.valueOf(getTimestamp()), getDescription());
    }

    private long parseTimestamp(@Nullable String str) {
        if (str == null) {
            return -1L;
        }
        try {
            return convertFromExifDateTime(str).getTime();
        } catch (ParseException unused) {
            return -1L;
        }
    }
}
