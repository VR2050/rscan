package im.uwrkaxlmjj.messenger.time;

import com.blankj.utilcode.constant.TimeConstants;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.text.DateFormatSymbols;
import java.text.FieldPosition;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/* JADX INFO: loaded from: classes2.dex */
public class FastDatePrinter implements DatePrinter, Serializable {
    public static final int FULL = 0;
    public static final int LONG = 1;
    public static final int MEDIUM = 2;
    public static final int SHORT = 3;
    private static final ConcurrentMap<TimeZoneDisplayKey, String> cTimeZoneDisplayCache = new ConcurrentHashMap(7);
    private static final long serialVersionUID = 1;
    private final Locale mLocale;
    private transient int mMaxLengthEstimate;
    private final String mPattern;
    private transient Rule[] mRules;
    private final TimeZone mTimeZone;

    private interface NumberRule extends Rule {
        void appendTo(StringBuffer stringBuffer, int i);
    }

    private interface Rule {
        void appendTo(StringBuffer stringBuffer, Calendar calendar);

        int estimateLength();
    }

    protected FastDatePrinter(String pattern, TimeZone timeZone, Locale locale) {
        this.mPattern = pattern;
        this.mTimeZone = timeZone;
        this.mLocale = locale;
        init();
    }

    private void init() {
        List<Rule> rulesList = parsePattern();
        Rule[] ruleArr = (Rule[]) rulesList.toArray(new Rule[rulesList.size()]);
        this.mRules = ruleArr;
        int len = 0;
        int i = ruleArr.length;
        while (true) {
            i--;
            if (i >= 0) {
                len += this.mRules[i].estimateLength();
            } else {
                this.mMaxLengthEstimate = len;
                return;
            }
        }
    }

    protected List<Rule> parsePattern() {
        String[] ERAs;
        String[] weekdays;
        Rule rule;
        DateFormatSymbols symbols = new DateFormatSymbols(this.mLocale);
        List<Rule> rules = new ArrayList<>();
        String[] ERAs2 = symbols.getEras();
        String[] months = symbols.getMonths();
        String[] shortMonths = symbols.getShortMonths();
        String[] weekdays2 = symbols.getWeekdays();
        String[] shortWeekdays = symbols.getShortWeekdays();
        String[] AmPmStrings = symbols.getAmPmStrings();
        int length = this.mPattern.length();
        int[] indexRef = new int[1];
        int i = 0;
        while (i < length) {
            indexRef[0] = i;
            String token = parseToken(this.mPattern, indexRef);
            int i2 = indexRef[0];
            int tokenLen = token.length();
            if (tokenLen != 0) {
                char c = token.charAt(0);
                DateFormatSymbols symbols2 = symbols;
                if (c != 'y') {
                    if (c == 'z') {
                        weekdays = weekdays2;
                        if (tokenLen >= 4) {
                            ERAs = ERAs2;
                            rule = new TimeZoneNameRule(this.mTimeZone, this.mLocale, 1);
                        } else {
                            ERAs = ERAs2;
                            rule = new TimeZoneNameRule(this.mTimeZone, this.mLocale, 0);
                        }
                    } else {
                        switch (c) {
                            case '\'':
                                weekdays = weekdays2;
                                String sub = token.substring(1);
                                if (sub.length() == 1) {
                                    rule = new CharacterLiteral(sub.charAt(0));
                                    ERAs = ERAs2;
                                } else {
                                    rule = new StringLiteral(sub);
                                    ERAs = ERAs2;
                                }
                                break;
                            case 'S':
                                weekdays = weekdays2;
                                rule = selectNumberRule(14, tokenLen);
                                ERAs = ERAs2;
                                break;
                            case 'W':
                                weekdays = weekdays2;
                                rule = selectNumberRule(4, tokenLen);
                                ERAs = ERAs2;
                                break;
                            case 'Z':
                                weekdays = weekdays2;
                                if (tokenLen == 1) {
                                    rule = TimeZoneNumberRule.INSTANCE_NO_COLON;
                                    ERAs = ERAs2;
                                } else {
                                    rule = TimeZoneNumberRule.INSTANCE_COLON;
                                    ERAs = ERAs2;
                                }
                                break;
                            case 'a':
                                weekdays = weekdays2;
                                rule = new TextField(9, AmPmStrings);
                                ERAs = ERAs2;
                                break;
                            case 'd':
                                weekdays = weekdays2;
                                rule = selectNumberRule(5, tokenLen);
                                ERAs = ERAs2;
                                break;
                            case 'h':
                                weekdays = weekdays2;
                                rule = new TwelveHourField(selectNumberRule(10, tokenLen));
                                ERAs = ERAs2;
                                break;
                            case 'k':
                                weekdays = weekdays2;
                                rule = new TwentyFourHourField(selectNumberRule(11, tokenLen));
                                ERAs = ERAs2;
                                break;
                            case 'm':
                                weekdays = weekdays2;
                                rule = selectNumberRule(12, tokenLen);
                                ERAs = ERAs2;
                                break;
                            case 's':
                                weekdays = weekdays2;
                                rule = selectNumberRule(13, tokenLen);
                                ERAs = ERAs2;
                                break;
                            case 'w':
                                weekdays = weekdays2;
                                rule = selectNumberRule(3, tokenLen);
                                ERAs = ERAs2;
                                break;
                            default:
                                switch (c) {
                                    case 'D':
                                        weekdays = weekdays2;
                                        rule = selectNumberRule(6, tokenLen);
                                        ERAs = ERAs2;
                                        break;
                                    case 'E':
                                        weekdays = weekdays2;
                                        rule = new TextField(7, tokenLen < 4 ? shortWeekdays : weekdays);
                                        ERAs = ERAs2;
                                        break;
                                    case 'F':
                                        weekdays = weekdays2;
                                        rule = selectNumberRule(8, tokenLen);
                                        ERAs = ERAs2;
                                        break;
                                    case 'G':
                                        weekdays = weekdays2;
                                        rule = new TextField(0, ERAs2);
                                        ERAs = ERAs2;
                                        break;
                                    case 'H':
                                        weekdays = weekdays2;
                                        rule = selectNumberRule(11, tokenLen);
                                        ERAs = ERAs2;
                                        break;
                                    default:
                                        switch (c) {
                                            case 'K':
                                                weekdays = weekdays2;
                                                rule = selectNumberRule(10, tokenLen);
                                                ERAs = ERAs2;
                                                break;
                                            case 'L':
                                                weekdays = weekdays2;
                                                if (tokenLen >= 4) {
                                                    rule = new TextField(2, months);
                                                    ERAs = ERAs2;
                                                } else if (tokenLen == 3) {
                                                    rule = new TextField(2, shortMonths);
                                                    ERAs = ERAs2;
                                                } else if (tokenLen == 2) {
                                                    rule = TwoDigitMonthField.INSTANCE;
                                                    ERAs = ERAs2;
                                                } else {
                                                    rule = UnpaddedMonthField.INSTANCE;
                                                    ERAs = ERAs2;
                                                }
                                                break;
                                            case 'M':
                                                weekdays = weekdays2;
                                                if (tokenLen >= 4) {
                                                    rule = new TextField(2, months);
                                                    ERAs = ERAs2;
                                                } else if (tokenLen == 3) {
                                                    rule = new TextField(2, shortMonths);
                                                    ERAs = ERAs2;
                                                } else if (tokenLen == 2) {
                                                    rule = TwoDigitMonthField.INSTANCE;
                                                    ERAs = ERAs2;
                                                } else {
                                                    rule = UnpaddedMonthField.INSTANCE;
                                                    ERAs = ERAs2;
                                                }
                                                break;
                                            default:
                                                throw new IllegalArgumentException("Illegal pattern component: " + token);
                                        }
                                        break;
                                }
                                break;
                        }
                    }
                } else {
                    ERAs = ERAs2;
                    weekdays = weekdays2;
                    rule = tokenLen != 2 ? selectNumberRule(1, tokenLen >= 4 ? tokenLen : 4) : TwoDigitYearField.INSTANCE;
                }
                rules.add(rule);
                i = i2 + 1;
                symbols = symbols2;
                ERAs2 = ERAs;
                weekdays2 = weekdays;
            } else {
                return rules;
            }
        }
        return rules;
    }

    protected String parseToken(String pattern, int[] indexRef) {
        StringBuilder buf = new StringBuilder();
        int i = indexRef[0];
        int length = pattern.length();
        char c = pattern.charAt(i);
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
            buf.append(c);
            while (i + 1 < length) {
                char peek = pattern.charAt(i + 1);
                if (peek != c) {
                    break;
                }
                buf.append(c);
                i++;
            }
        } else {
            buf.append('\'');
            boolean inLiteral = false;
            while (i < length) {
                char c2 = pattern.charAt(i);
                if (c2 == '\'') {
                    if (i + 1 < length && pattern.charAt(i + 1) == '\'') {
                        i++;
                        buf.append(c2);
                    } else {
                        inLiteral = !inLiteral;
                    }
                } else {
                    if (!inLiteral && ((c2 >= 'A' && c2 <= 'Z') || (c2 >= 'a' && c2 <= 'z'))) {
                        i--;
                        break;
                    }
                    buf.append(c2);
                }
                i++;
            }
        }
        indexRef[0] = i;
        return buf.toString();
    }

    protected NumberRule selectNumberRule(int field, int padding) {
        if (padding == 1) {
            return new UnpaddedNumberField(field);
        }
        if (padding == 2) {
            return new TwoDigitNumberField(field);
        }
        return new PaddedNumberField(field, padding);
    }

    @Override // im.uwrkaxlmjj.messenger.time.DatePrinter
    public StringBuffer format(Object obj, StringBuffer toAppendTo, FieldPosition pos) {
        if (obj instanceof Date) {
            return format((Date) obj, toAppendTo);
        }
        if (obj instanceof Calendar) {
            return format((Calendar) obj, toAppendTo);
        }
        if (obj instanceof Long) {
            return format(((Long) obj).longValue(), toAppendTo);
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Unknown class: ");
        sb.append(obj == null ? "<null>" : obj.getClass().getName());
        throw new IllegalArgumentException(sb.toString());
    }

    @Override // im.uwrkaxlmjj.messenger.time.DatePrinter
    public String format(long millis) {
        Calendar c = newCalendar();
        c.setTimeInMillis(millis);
        return applyRulesToString(c);
    }

    private String applyRulesToString(Calendar c) {
        return applyRules(c, new StringBuffer(this.mMaxLengthEstimate)).toString();
    }

    private GregorianCalendar newCalendar() {
        return new GregorianCalendar(this.mTimeZone, this.mLocale);
    }

    @Override // im.uwrkaxlmjj.messenger.time.DatePrinter
    public String format(Date date) {
        Calendar c = newCalendar();
        c.setTime(date);
        return applyRulesToString(c);
    }

    @Override // im.uwrkaxlmjj.messenger.time.DatePrinter
    public String format(Calendar calendar) {
        return format(calendar, new StringBuffer(this.mMaxLengthEstimate)).toString();
    }

    @Override // im.uwrkaxlmjj.messenger.time.DatePrinter
    public StringBuffer format(long millis, StringBuffer buf) {
        return format(new Date(millis), buf);
    }

    @Override // im.uwrkaxlmjj.messenger.time.DatePrinter
    public StringBuffer format(Date date, StringBuffer buf) {
        Calendar c = newCalendar();
        c.setTime(date);
        return applyRules(c, buf);
    }

    @Override // im.uwrkaxlmjj.messenger.time.DatePrinter
    public StringBuffer format(Calendar calendar, StringBuffer buf) {
        return applyRules(calendar, buf);
    }

    protected StringBuffer applyRules(Calendar calendar, StringBuffer buf) {
        for (Rule rule : this.mRules) {
            rule.appendTo(buf, calendar);
        }
        return buf;
    }

    @Override // im.uwrkaxlmjj.messenger.time.DatePrinter
    public String getPattern() {
        return this.mPattern;
    }

    @Override // im.uwrkaxlmjj.messenger.time.DatePrinter
    public TimeZone getTimeZone() {
        return this.mTimeZone;
    }

    @Override // im.uwrkaxlmjj.messenger.time.DatePrinter
    public Locale getLocale() {
        return this.mLocale;
    }

    public int getMaxLengthEstimate() {
        return this.mMaxLengthEstimate;
    }

    public boolean equals(Object obj) {
        if (!(obj instanceof FastDatePrinter)) {
            return false;
        }
        FastDatePrinter other = (FastDatePrinter) obj;
        return this.mPattern.equals(other.mPattern) && this.mTimeZone.equals(other.mTimeZone) && this.mLocale.equals(other.mLocale);
    }

    public int hashCode() {
        return this.mPattern.hashCode() + ((this.mTimeZone.hashCode() + (this.mLocale.hashCode() * 13)) * 13);
    }

    public String toString() {
        return "FastDatePrinter[" + this.mPattern + "," + this.mLocale + "," + this.mTimeZone.getID() + "]";
    }

    private void readObject(ObjectInputStream in) throws ClassNotFoundException, IOException {
        in.defaultReadObject();
        init();
    }

    private static class CharacterLiteral implements Rule {
        private final char mValue;

        CharacterLiteral(char value) {
            this.mValue = value;
        }

        @Override // im.uwrkaxlmjj.messenger.time.FastDatePrinter.Rule
        public int estimateLength() {
            return 1;
        }

        @Override // im.uwrkaxlmjj.messenger.time.FastDatePrinter.Rule
        public void appendTo(StringBuffer buffer, Calendar calendar) {
            buffer.append(this.mValue);
        }
    }

    private static class StringLiteral implements Rule {
        private final String mValue;

        StringLiteral(String value) {
            this.mValue = value;
        }

        @Override // im.uwrkaxlmjj.messenger.time.FastDatePrinter.Rule
        public int estimateLength() {
            return this.mValue.length();
        }

        @Override // im.uwrkaxlmjj.messenger.time.FastDatePrinter.Rule
        public void appendTo(StringBuffer buffer, Calendar calendar) {
            buffer.append(this.mValue);
        }
    }

    private static class TextField implements Rule {
        private final int mField;
        private final String[] mValues;

        TextField(int field, String[] values) {
            this.mField = field;
            this.mValues = values;
        }

        @Override // im.uwrkaxlmjj.messenger.time.FastDatePrinter.Rule
        public int estimateLength() {
            int max = 0;
            int i = this.mValues.length;
            while (true) {
                i--;
                if (i >= 0) {
                    int len = this.mValues[i].length();
                    if (len > max) {
                        max = len;
                    }
                } else {
                    return max;
                }
            }
        }

        @Override // im.uwrkaxlmjj.messenger.time.FastDatePrinter.Rule
        public void appendTo(StringBuffer buffer, Calendar calendar) {
            buffer.append(this.mValues[calendar.get(this.mField)]);
        }
    }

    private static class UnpaddedNumberField implements NumberRule {
        private final int mField;

        UnpaddedNumberField(int field) {
            this.mField = field;
        }

        @Override // im.uwrkaxlmjj.messenger.time.FastDatePrinter.Rule
        public int estimateLength() {
            return 4;
        }

        @Override // im.uwrkaxlmjj.messenger.time.FastDatePrinter.Rule
        public void appendTo(StringBuffer buffer, Calendar calendar) {
            appendTo(buffer, calendar.get(this.mField));
        }

        @Override // im.uwrkaxlmjj.messenger.time.FastDatePrinter.NumberRule
        public final void appendTo(StringBuffer buffer, int value) {
            if (value < 10) {
                buffer.append((char) (value + 48));
            } else if (value < 100) {
                buffer.append((char) ((value / 10) + 48));
                buffer.append((char) ((value % 10) + 48));
            } else {
                buffer.append(Integer.toString(value));
            }
        }
    }

    private static class UnpaddedMonthField implements NumberRule {
        static final UnpaddedMonthField INSTANCE = new UnpaddedMonthField();

        UnpaddedMonthField() {
        }

        @Override // im.uwrkaxlmjj.messenger.time.FastDatePrinter.Rule
        public int estimateLength() {
            return 2;
        }

        @Override // im.uwrkaxlmjj.messenger.time.FastDatePrinter.Rule
        public void appendTo(StringBuffer buffer, Calendar calendar) {
            appendTo(buffer, calendar.get(2) + 1);
        }

        @Override // im.uwrkaxlmjj.messenger.time.FastDatePrinter.NumberRule
        public final void appendTo(StringBuffer buffer, int value) {
            if (value < 10) {
                buffer.append((char) (value + 48));
            } else {
                buffer.append((char) ((value / 10) + 48));
                buffer.append((char) ((value % 10) + 48));
            }
        }
    }

    private static class PaddedNumberField implements NumberRule {
        private final int mField;
        private final int mSize;

        PaddedNumberField(int field, int size) {
            if (size < 3) {
                throw new IllegalArgumentException();
            }
            this.mField = field;
            this.mSize = size;
        }

        @Override // im.uwrkaxlmjj.messenger.time.FastDatePrinter.Rule
        public int estimateLength() {
            return 4;
        }

        @Override // im.uwrkaxlmjj.messenger.time.FastDatePrinter.Rule
        public void appendTo(StringBuffer buffer, Calendar calendar) {
            appendTo(buffer, calendar.get(this.mField));
        }

        @Override // im.uwrkaxlmjj.messenger.time.FastDatePrinter.NumberRule
        public final void appendTo(StringBuffer buffer, int value) {
            int digits;
            if (value < 100) {
                int i = this.mSize;
                while (true) {
                    i--;
                    if (i >= 2) {
                        buffer.append('0');
                    } else {
                        int i2 = value / 10;
                        buffer.append((char) (i2 + 48));
                        buffer.append((char) ((value % 10) + 48));
                        return;
                    }
                }
            } else {
                if (value < 1000) {
                    digits = 3;
                } else {
                    digits = Integer.toString(value).length();
                }
                int i3 = this.mSize;
                while (true) {
                    i3--;
                    if (i3 >= digits) {
                        buffer.append('0');
                    } else {
                        buffer.append(Integer.toString(value));
                        return;
                    }
                }
            }
        }
    }

    private static class TwoDigitNumberField implements NumberRule {
        private final int mField;

        TwoDigitNumberField(int field) {
            this.mField = field;
        }

        @Override // im.uwrkaxlmjj.messenger.time.FastDatePrinter.Rule
        public int estimateLength() {
            return 2;
        }

        @Override // im.uwrkaxlmjj.messenger.time.FastDatePrinter.Rule
        public void appendTo(StringBuffer buffer, Calendar calendar) {
            appendTo(buffer, calendar.get(this.mField));
        }

        @Override // im.uwrkaxlmjj.messenger.time.FastDatePrinter.NumberRule
        public final void appendTo(StringBuffer buffer, int value) {
            if (value < 100) {
                buffer.append((char) ((value / 10) + 48));
                buffer.append((char) ((value % 10) + 48));
            } else {
                buffer.append(Integer.toString(value));
            }
        }
    }

    private static class TwoDigitYearField implements NumberRule {
        static final TwoDigitYearField INSTANCE = new TwoDigitYearField();

        TwoDigitYearField() {
        }

        @Override // im.uwrkaxlmjj.messenger.time.FastDatePrinter.Rule
        public int estimateLength() {
            return 2;
        }

        @Override // im.uwrkaxlmjj.messenger.time.FastDatePrinter.Rule
        public void appendTo(StringBuffer buffer, Calendar calendar) {
            appendTo(buffer, calendar.get(1) % 100);
        }

        @Override // im.uwrkaxlmjj.messenger.time.FastDatePrinter.NumberRule
        public final void appendTo(StringBuffer buffer, int value) {
            buffer.append((char) ((value / 10) + 48));
            buffer.append((char) ((value % 10) + 48));
        }
    }

    private static class TwoDigitMonthField implements NumberRule {
        static final TwoDigitMonthField INSTANCE = new TwoDigitMonthField();

        TwoDigitMonthField() {
        }

        @Override // im.uwrkaxlmjj.messenger.time.FastDatePrinter.Rule
        public int estimateLength() {
            return 2;
        }

        @Override // im.uwrkaxlmjj.messenger.time.FastDatePrinter.Rule
        public void appendTo(StringBuffer buffer, Calendar calendar) {
            appendTo(buffer, calendar.get(2) + 1);
        }

        @Override // im.uwrkaxlmjj.messenger.time.FastDatePrinter.NumberRule
        public final void appendTo(StringBuffer buffer, int value) {
            buffer.append((char) ((value / 10) + 48));
            buffer.append((char) ((value % 10) + 48));
        }
    }

    private static class TwelveHourField implements NumberRule {
        private final NumberRule mRule;

        TwelveHourField(NumberRule rule) {
            this.mRule = rule;
        }

        @Override // im.uwrkaxlmjj.messenger.time.FastDatePrinter.Rule
        public int estimateLength() {
            return this.mRule.estimateLength();
        }

        @Override // im.uwrkaxlmjj.messenger.time.FastDatePrinter.Rule
        public void appendTo(StringBuffer buffer, Calendar calendar) {
            int value = calendar.get(10);
            if (value == 0) {
                value = calendar.getLeastMaximum(10) + 1;
            }
            this.mRule.appendTo(buffer, value);
        }

        @Override // im.uwrkaxlmjj.messenger.time.FastDatePrinter.NumberRule
        public void appendTo(StringBuffer buffer, int value) {
            this.mRule.appendTo(buffer, value);
        }
    }

    private static class TwentyFourHourField implements NumberRule {
        private final NumberRule mRule;

        TwentyFourHourField(NumberRule rule) {
            this.mRule = rule;
        }

        @Override // im.uwrkaxlmjj.messenger.time.FastDatePrinter.Rule
        public int estimateLength() {
            return this.mRule.estimateLength();
        }

        @Override // im.uwrkaxlmjj.messenger.time.FastDatePrinter.Rule
        public void appendTo(StringBuffer buffer, Calendar calendar) {
            int value = calendar.get(11);
            if (value == 0) {
                value = calendar.getMaximum(11) + 1;
            }
            this.mRule.appendTo(buffer, value);
        }

        @Override // im.uwrkaxlmjj.messenger.time.FastDatePrinter.NumberRule
        public void appendTo(StringBuffer buffer, int value) {
            this.mRule.appendTo(buffer, value);
        }
    }

    static String getTimeZoneDisplay(TimeZone tz, boolean daylight, int style, Locale locale) {
        TimeZoneDisplayKey key = new TimeZoneDisplayKey(tz, daylight, style, locale);
        String value = cTimeZoneDisplayCache.get(key);
        if (value == null) {
            String value2 = tz.getDisplayName(daylight, style, locale);
            String prior = cTimeZoneDisplayCache.putIfAbsent(key, value2);
            if (prior != null) {
                return prior;
            }
            return value2;
        }
        return value;
    }

    private static class TimeZoneNameRule implements Rule {
        private final String mDaylight;
        private final Locale mLocale;
        private final String mStandard;
        private final int mStyle;

        TimeZoneNameRule(TimeZone timeZone, Locale locale, int style) {
            this.mLocale = locale;
            this.mStyle = style;
            this.mStandard = FastDatePrinter.getTimeZoneDisplay(timeZone, false, style, locale);
            this.mDaylight = FastDatePrinter.getTimeZoneDisplay(timeZone, true, style, locale);
        }

        @Override // im.uwrkaxlmjj.messenger.time.FastDatePrinter.Rule
        public int estimateLength() {
            return Math.max(this.mStandard.length(), this.mDaylight.length());
        }

        @Override // im.uwrkaxlmjj.messenger.time.FastDatePrinter.Rule
        public void appendTo(StringBuffer buffer, Calendar calendar) {
            TimeZone zone = calendar.getTimeZone();
            if (zone.useDaylightTime() && calendar.get(16) != 0) {
                buffer.append(FastDatePrinter.getTimeZoneDisplay(zone, true, this.mStyle, this.mLocale));
            } else {
                buffer.append(FastDatePrinter.getTimeZoneDisplay(zone, false, this.mStyle, this.mLocale));
            }
        }
    }

    private static class TimeZoneNumberRule implements Rule {
        static final TimeZoneNumberRule INSTANCE_COLON = new TimeZoneNumberRule(true);
        static final TimeZoneNumberRule INSTANCE_NO_COLON = new TimeZoneNumberRule(false);
        final boolean mColon;

        TimeZoneNumberRule(boolean colon) {
            this.mColon = colon;
        }

        @Override // im.uwrkaxlmjj.messenger.time.FastDatePrinter.Rule
        public int estimateLength() {
            return 5;
        }

        @Override // im.uwrkaxlmjj.messenger.time.FastDatePrinter.Rule
        public void appendTo(StringBuffer buffer, Calendar calendar) {
            int offset = calendar.get(15) + calendar.get(16);
            if (offset < 0) {
                buffer.append('-');
                offset = -offset;
            } else {
                buffer.append('+');
            }
            int hours = offset / TimeConstants.HOUR;
            buffer.append((char) ((hours / 10) + 48));
            buffer.append((char) ((hours % 10) + 48));
            if (this.mColon) {
                buffer.append(':');
            }
            int minutes = (offset / 60000) - (hours * 60);
            buffer.append((char) ((minutes / 10) + 48));
            buffer.append((char) ((minutes % 10) + 48));
        }
    }

    private static class TimeZoneDisplayKey {
        private final Locale mLocale;
        private final int mStyle;
        private final TimeZone mTimeZone;

        TimeZoneDisplayKey(TimeZone timeZone, boolean daylight, int style, Locale locale) {
            this.mTimeZone = timeZone;
            if (daylight) {
                this.mStyle = Integer.MIN_VALUE | style;
            } else {
                this.mStyle = style;
            }
            this.mLocale = locale;
        }

        public int hashCode() {
            return (((this.mStyle * 31) + this.mLocale.hashCode()) * 31) + this.mTimeZone.hashCode();
        }

        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof TimeZoneDisplayKey)) {
                return false;
            }
            TimeZoneDisplayKey other = (TimeZoneDisplayKey) obj;
            return this.mTimeZone.equals(other.mTimeZone) && this.mStyle == other.mStyle && this.mLocale.equals(other.mLocale);
        }
    }
}
