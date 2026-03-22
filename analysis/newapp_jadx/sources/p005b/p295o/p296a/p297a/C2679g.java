package p005b.p295o.p296a.p297a;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Objects;
import java.util.Vector;

/* renamed from: b.o.a.a.g */
/* loaded from: classes2.dex */
public class C2679g {

    /* renamed from: a */
    public static final Integer f7286a = new Integer(1);

    /* renamed from: b */
    public static final Integer f7287b = new Integer(2);

    /* renamed from: c */
    public static final Integer f7288c = new Integer(3);

    /* renamed from: d */
    public static final Integer f7289d = new Integer(4);

    /* renamed from: e */
    public static final Integer f7290e = new Integer(5);

    /* renamed from: f */
    public static final Integer f7291f = new Integer(6);

    /* renamed from: g */
    public static final Integer f7292g = new Integer(7);

    /* renamed from: h */
    public static final Integer f7293h = new Integer(8);

    /* renamed from: i */
    public static final Integer f7294i = new Integer(9);

    /* renamed from: j */
    public static final Integer f7295j = new Integer(10);

    /* renamed from: k */
    public final Vector f7296k = new Vector();

    /* renamed from: l */
    public Hashtable f7297l = new Hashtable();

    /* renamed from: b */
    public static Integer m3184b(AbstractC2678f abstractC2678f) {
        return new Integer(System.identityHashCode(abstractC2678f));
    }

    /* renamed from: a */
    public void m3185a(AbstractC2678f abstractC2678f, int i2) {
        Integer num;
        this.f7296k.addElement(abstractC2678f);
        switch (i2) {
            case 1:
                num = f7286a;
                break;
            case 2:
                num = f7287b;
                break;
            case 3:
                num = f7288c;
                break;
            case 4:
                num = f7289d;
                break;
            case 5:
                num = f7290e;
                break;
            case 6:
                num = f7291f;
                break;
            case 7:
                num = f7292g;
                break;
            case 8:
                num = f7293h;
                break;
            case 9:
                num = f7294i;
                break;
            case 10:
                num = f7295j;
                break;
            default:
                num = new Integer(i2);
                break;
        }
        this.f7297l.put(m3184b(abstractC2678f), num);
    }

    /* renamed from: c */
    public void m3186c() {
        this.f7296k.removeAllElements();
        this.f7297l.clear();
    }

    public String toString() {
        try {
            StringBuffer stringBuffer = new StringBuffer("{ ");
            Enumeration elements = this.f7296k.elements();
            while (elements.hasMoreElements()) {
                Object nextElement = elements.nextElement();
                if (nextElement instanceof String) {
                    stringBuffer.append("String(" + nextElement + ") ");
                } else {
                    AbstractC2678f abstractC2678f = (AbstractC2678f) nextElement;
                    StringBuilder sb = new StringBuilder();
                    sb.append("Node(");
                    Objects.requireNonNull(abstractC2678f);
                    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                    OutputStreamWriter outputStreamWriter = new OutputStreamWriter(byteArrayOutputStream);
                    abstractC2678f.mo3172e(outputStreamWriter);
                    outputStreamWriter.flush();
                    sb.append(new String(byteArrayOutputStream.toByteArray()));
                    sb.append(")[");
                    sb.append(this.f7297l.get(m3184b(abstractC2678f)));
                    sb.append("] ");
                    stringBuffer.append(sb.toString());
                }
            }
            stringBuffer.append("}");
            return stringBuffer.toString();
        } catch (IOException e2) {
            return e2.toString();
        }
    }
}
