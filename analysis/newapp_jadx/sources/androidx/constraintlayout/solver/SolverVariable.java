package androidx.constraintlayout.solver;

import androidx.exifinterface.media.ExifInterface;
import java.util.Arrays;
import java.util.HashSet;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p143g.p144a.p146l.C1568e;

/* loaded from: classes.dex */
public class SolverVariable {
    private static final boolean INTERNAL_DEBUG = false;
    public static final int MAX_STRENGTH = 9;
    public static final int STRENGTH_BARRIER = 6;
    public static final int STRENGTH_CENTERING = 7;
    public static final int STRENGTH_EQUALITY = 5;
    public static final int STRENGTH_FIXED = 8;
    public static final int STRENGTH_HIGH = 3;
    public static final int STRENGTH_HIGHEST = 4;
    public static final int STRENGTH_LOW = 1;
    public static final int STRENGTH_MEDIUM = 2;
    public static final int STRENGTH_NONE = 0;
    private static final boolean VAR_USE_HASH = false;
    private static int uniqueConstantId = 1;
    private static int uniqueErrorId = 1;
    private static int uniqueId = 1;
    private static int uniqueSlackId = 1;
    private static int uniqueUnrestrictedId = 1;
    public float computedValue;
    public int definitionId;
    public float[] goalStrengthVector;

    /* renamed from: id */
    public int f136id;
    public boolean inGoal;
    public HashSet<ArrayRow> inRows;
    public boolean isFinalValue;
    public boolean isSynonym;
    public ArrayRow[] mClientEquations;
    public int mClientEquationsCount;
    private String mName;
    public Type mType;
    public int strength;
    public float[] strengthVector;
    public int synonym;
    public float synonymDelta;
    public int usageInRowCount;

    /* renamed from: androidx.constraintlayout.solver.SolverVariable$1 */
    public static /* synthetic */ class C02391 {
        public static final /* synthetic */ int[] $SwitchMap$androidx$constraintlayout$solver$SolverVariable$Type;

        static {
            Type.values();
            int[] iArr = new int[5];
            $SwitchMap$androidx$constraintlayout$solver$SolverVariable$Type = iArr;
            try {
                iArr[Type.UNRESTRICTED.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                $SwitchMap$androidx$constraintlayout$solver$SolverVariable$Type[Type.CONSTANT.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                $SwitchMap$androidx$constraintlayout$solver$SolverVariable$Type[Type.SLACK.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            try {
                $SwitchMap$androidx$constraintlayout$solver$SolverVariable$Type[Type.ERROR.ordinal()] = 4;
            } catch (NoSuchFieldError unused4) {
            }
            try {
                $SwitchMap$androidx$constraintlayout$solver$SolverVariable$Type[Type.UNKNOWN.ordinal()] = 5;
            } catch (NoSuchFieldError unused5) {
            }
        }
    }

    public enum Type {
        UNRESTRICTED,
        CONSTANT,
        SLACK,
        ERROR,
        UNKNOWN
    }

    public SolverVariable(String str, Type type) {
        this.f136id = -1;
        this.definitionId = -1;
        this.strength = 0;
        this.isFinalValue = false;
        this.strengthVector = new float[9];
        this.goalStrengthVector = new float[9];
        this.mClientEquations = new ArrayRow[16];
        this.mClientEquationsCount = 0;
        this.usageInRowCount = 0;
        this.isSynonym = false;
        this.synonym = -1;
        this.synonymDelta = 0.0f;
        this.inRows = null;
        this.mName = str;
        this.mType = type;
    }

    private static String getUniqueName(Type type, String str) {
        if (str != null) {
            StringBuilder m586H = C1499a.m586H(str);
            m586H.append(uniqueErrorId);
            return m586H.toString();
        }
        int ordinal = type.ordinal();
        if (ordinal == 0) {
            StringBuilder m586H2 = C1499a.m586H("U");
            int i2 = uniqueUnrestrictedId + 1;
            uniqueUnrestrictedId = i2;
            m586H2.append(i2);
            return m586H2.toString();
        }
        if (ordinal == 1) {
            StringBuilder m586H3 = C1499a.m586H("C");
            int i3 = uniqueConstantId + 1;
            uniqueConstantId = i3;
            m586H3.append(i3);
            return m586H3.toString();
        }
        if (ordinal == 2) {
            StringBuilder m586H4 = C1499a.m586H(ExifInterface.LATITUDE_SOUTH);
            int i4 = uniqueSlackId + 1;
            uniqueSlackId = i4;
            m586H4.append(i4);
            return m586H4.toString();
        }
        if (ordinal == 3) {
            StringBuilder m586H5 = C1499a.m586H(C1568e.f1949a);
            int i5 = uniqueErrorId + 1;
            uniqueErrorId = i5;
            m586H5.append(i5);
            return m586H5.toString();
        }
        if (ordinal != 4) {
            throw new AssertionError(type.name());
        }
        StringBuilder m586H6 = C1499a.m586H(ExifInterface.GPS_MEASUREMENT_INTERRUPTED);
        int i6 = uniqueId + 1;
        uniqueId = i6;
        m586H6.append(i6);
        return m586H6.toString();
    }

    public static void increaseErrorId() {
        uniqueErrorId++;
    }

    public final void addToRow(ArrayRow arrayRow) {
        int i2 = 0;
        while (true) {
            int i3 = this.mClientEquationsCount;
            if (i2 >= i3) {
                ArrayRow[] arrayRowArr = this.mClientEquations;
                if (i3 >= arrayRowArr.length) {
                    this.mClientEquations = (ArrayRow[]) Arrays.copyOf(arrayRowArr, arrayRowArr.length * 2);
                }
                ArrayRow[] arrayRowArr2 = this.mClientEquations;
                int i4 = this.mClientEquationsCount;
                arrayRowArr2[i4] = arrayRow;
                this.mClientEquationsCount = i4 + 1;
                return;
            }
            if (this.mClientEquations[i2] == arrayRow) {
                return;
            } else {
                i2++;
            }
        }
    }

    public void clearStrengths() {
        for (int i2 = 0; i2 < 9; i2++) {
            this.strengthVector[i2] = 0.0f;
        }
    }

    public String getName() {
        return this.mName;
    }

    public final void removeFromRow(ArrayRow arrayRow) {
        int i2 = this.mClientEquationsCount;
        int i3 = 0;
        while (i3 < i2) {
            if (this.mClientEquations[i3] == arrayRow) {
                while (i3 < i2 - 1) {
                    ArrayRow[] arrayRowArr = this.mClientEquations;
                    int i4 = i3 + 1;
                    arrayRowArr[i3] = arrayRowArr[i4];
                    i3 = i4;
                }
                this.mClientEquationsCount--;
                return;
            }
            i3++;
        }
    }

    public void reset() {
        this.mName = null;
        this.mType = Type.UNKNOWN;
        this.strength = 0;
        this.f136id = -1;
        this.definitionId = -1;
        this.computedValue = 0.0f;
        this.isFinalValue = false;
        this.isSynonym = false;
        this.synonym = -1;
        this.synonymDelta = 0.0f;
        int i2 = this.mClientEquationsCount;
        for (int i3 = 0; i3 < i2; i3++) {
            this.mClientEquations[i3] = null;
        }
        this.mClientEquationsCount = 0;
        this.usageInRowCount = 0;
        this.inGoal = false;
        Arrays.fill(this.goalStrengthVector, 0.0f);
    }

    public void setFinalValue(LinearSystem linearSystem, float f2) {
        this.computedValue = f2;
        this.isFinalValue = true;
        this.isSynonym = false;
        this.synonym = -1;
        this.synonymDelta = 0.0f;
        int i2 = this.mClientEquationsCount;
        this.definitionId = -1;
        for (int i3 = 0; i3 < i2; i3++) {
            this.mClientEquations[i3].updateFromFinalVariable(linearSystem, this, false);
        }
        this.mClientEquationsCount = 0;
    }

    public void setName(String str) {
        this.mName = str;
    }

    public void setSynonym(LinearSystem linearSystem, SolverVariable solverVariable, float f2) {
        this.isSynonym = true;
        this.synonym = solverVariable.f136id;
        this.synonymDelta = f2;
        int i2 = this.mClientEquationsCount;
        this.definitionId = -1;
        for (int i3 = 0; i3 < i2; i3++) {
            this.mClientEquations[i3].updateFromSynonymVariable(linearSystem, this, false);
        }
        this.mClientEquationsCount = 0;
        linearSystem.displayReadableRows();
    }

    public void setType(Type type, String str) {
        this.mType = type;
    }

    public String strengthsToString() {
        String str = this + "[";
        int i2 = 0;
        boolean z = false;
        boolean z2 = true;
        while (i2 < this.strengthVector.length) {
            StringBuilder m586H = C1499a.m586H(str);
            m586H.append(this.strengthVector[i2]);
            String sb = m586H.toString();
            float[] fArr = this.strengthVector;
            if (fArr[i2] > 0.0f) {
                z = false;
            } else if (fArr[i2] < 0.0f) {
                z = true;
            }
            if (fArr[i2] != 0.0f) {
                z2 = false;
            }
            str = i2 < fArr.length + (-1) ? C1499a.m637w(sb, ", ") : C1499a.m637w(sb, "] ");
            i2++;
        }
        if (z) {
            str = C1499a.m637w(str, " (-)");
        }
        return z2 ? C1499a.m637w(str, " (*)") : str;
    }

    public String toString() {
        if (this.mName != null) {
            StringBuilder m586H = C1499a.m586H("");
            m586H.append(this.mName);
            return m586H.toString();
        }
        StringBuilder m586H2 = C1499a.m586H("");
        m586H2.append(this.f136id);
        return m586H2.toString();
    }

    public final void updateReferencesWithNewDefinition(LinearSystem linearSystem, ArrayRow arrayRow) {
        int i2 = this.mClientEquationsCount;
        for (int i3 = 0; i3 < i2; i3++) {
            this.mClientEquations[i3].updateFromRow(linearSystem, arrayRow, false);
        }
        this.mClientEquationsCount = 0;
    }

    public SolverVariable(Type type, String str) {
        this.f136id = -1;
        this.definitionId = -1;
        this.strength = 0;
        this.isFinalValue = false;
        this.strengthVector = new float[9];
        this.goalStrengthVector = new float[9];
        this.mClientEquations = new ArrayRow[16];
        this.mClientEquationsCount = 0;
        this.usageInRowCount = 0;
        this.isSynonym = false;
        this.synonym = -1;
        this.synonymDelta = 0.0f;
        this.inRows = null;
        this.mType = type;
    }
}
