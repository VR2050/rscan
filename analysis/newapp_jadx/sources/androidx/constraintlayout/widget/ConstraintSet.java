package androidx.constraintlayout.widget;

import android.content.Context;
import android.content.res.TypedArray;
import android.content.res.XmlResourceParser;
import android.graphics.Color;
import android.util.AttributeSet;
import android.util.SparseArray;
import android.util.SparseIntArray;
import android.util.Xml;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.constraintlayout.motion.utils.Easing;
import androidx.constraintlayout.motion.widget.Debug;
import androidx.constraintlayout.motion.widget.MotionScene;
import androidx.constraintlayout.solver.widgets.ConstraintWidget;
import androidx.constraintlayout.solver.widgets.HelperWidget;
import androidx.constraintlayout.widget.C0257R;
import androidx.constraintlayout.widget.ConstraintAttribute;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.constraintlayout.widget.Constraints;
import com.google.android.material.shadow.ShadowDrawableWrapper;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import net.sourceforge.pinyin4j.ChineseToPinyinResource;
import org.xmlpull.v1.XmlPullParserException;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public class ConstraintSet {
    private static final int ALPHA = 43;
    private static final int ANIMATE_RELATIVE_TO = 64;
    private static final int BARRIER_ALLOWS_GONE_WIDGETS = 75;
    private static final int BARRIER_DIRECTION = 72;
    private static final int BARRIER_MARGIN = 73;
    private static final int BARRIER_TYPE = 1;
    public static final int BASELINE = 5;
    private static final int BASELINE_TO_BASELINE = 1;
    public static final int BOTTOM = 4;
    private static final int BOTTOM_MARGIN = 2;
    private static final int BOTTOM_TO_BOTTOM = 3;
    private static final int BOTTOM_TO_TOP = 4;
    public static final int CHAIN_PACKED = 2;
    public static final int CHAIN_SPREAD = 0;
    public static final int CHAIN_SPREAD_INSIDE = 1;
    private static final int CHAIN_USE_RTL = 71;
    private static final int CIRCLE = 61;
    private static final int CIRCLE_ANGLE = 63;
    private static final int CIRCLE_RADIUS = 62;
    private static final int CONSTRAINED_HEIGHT = 81;
    private static final int CONSTRAINED_WIDTH = 80;
    private static final int CONSTRAINT_REFERENCED_IDS = 74;
    private static final int CONSTRAINT_TAG = 77;
    private static final boolean DEBUG = false;
    private static final int DIMENSION_RATIO = 5;
    private static final int DRAW_PATH = 66;
    private static final int EDITOR_ABSOLUTE_X = 6;
    private static final int EDITOR_ABSOLUTE_Y = 7;
    private static final int ELEVATION = 44;
    public static final int END = 7;
    private static final int END_MARGIN = 8;
    private static final int END_TO_END = 9;
    private static final int END_TO_START = 10;
    private static final String ERROR_MESSAGE = "XML parser error must be within a Constraint ";
    public static final int GONE = 8;
    private static final int GONE_BOTTOM_MARGIN = 11;
    private static final int GONE_END_MARGIN = 12;
    private static final int GONE_LEFT_MARGIN = 13;
    private static final int GONE_RIGHT_MARGIN = 14;
    private static final int GONE_START_MARGIN = 15;
    private static final int GONE_TOP_MARGIN = 16;
    private static final int GUIDE_BEGIN = 17;
    private static final int GUIDE_END = 18;
    private static final int GUIDE_PERCENT = 19;
    private static final int HEIGHT_DEFAULT = 55;
    private static final int HEIGHT_MAX = 57;
    private static final int HEIGHT_MIN = 59;
    private static final int HEIGHT_PERCENT = 70;
    public static final int HORIZONTAL = 0;
    private static final int HORIZONTAL_BIAS = 20;
    public static final int HORIZONTAL_GUIDELINE = 0;
    private static final int HORIZONTAL_STYLE = 41;
    private static final int HORIZONTAL_WEIGHT = 39;
    public static final int INVISIBLE = 4;
    private static final int LAYOUT_HEIGHT = 21;
    private static final int LAYOUT_VISIBILITY = 22;
    private static final int LAYOUT_WIDTH = 23;
    public static final int LEFT = 1;
    private static final int LEFT_MARGIN = 24;
    private static final int LEFT_TO_LEFT = 25;
    private static final int LEFT_TO_RIGHT = 26;
    public static final int MATCH_CONSTRAINT = 0;
    public static final int MATCH_CONSTRAINT_SPREAD = 0;
    public static final int MATCH_CONSTRAINT_WRAP = 1;
    private static final int MOTION_STAGGER = 79;
    private static final int ORIENTATION = 27;
    public static final int PARENT_ID = 0;
    private static final int PATH_MOTION_ARC = 76;
    private static final int PROGRESS = 68;
    public static final int RIGHT = 2;
    private static final int RIGHT_MARGIN = 28;
    private static final int RIGHT_TO_LEFT = 29;
    private static final int RIGHT_TO_RIGHT = 30;
    private static final int ROTATION = 60;
    private static final int ROTATION_X = 45;
    private static final int ROTATION_Y = 46;
    private static final int SCALE_X = 47;
    private static final int SCALE_Y = 48;
    public static final int START = 6;
    private static final int START_MARGIN = 31;
    private static final int START_TO_END = 32;
    private static final int START_TO_START = 33;
    private static final String TAG = "ConstraintSet";
    public static final int TOP = 3;
    private static final int TOP_MARGIN = 34;
    private static final int TOP_TO_BOTTOM = 35;
    private static final int TOP_TO_TOP = 36;
    private static final int TRANSFORM_PIVOT_X = 49;
    private static final int TRANSFORM_PIVOT_Y = 50;
    private static final int TRANSITION_EASING = 65;
    private static final int TRANSITION_PATH_ROTATE = 67;
    private static final int TRANSLATION_X = 51;
    private static final int TRANSLATION_Y = 52;
    private static final int TRANSLATION_Z = 53;
    public static final int UNSET = -1;
    private static final int UNUSED = 82;
    public static final int VERTICAL = 1;
    private static final int VERTICAL_BIAS = 37;
    public static final int VERTICAL_GUIDELINE = 1;
    private static final int VERTICAL_STYLE = 42;
    private static final int VERTICAL_WEIGHT = 40;
    private static final int VIEW_ID = 38;
    private static final int[] VISIBILITY_FLAGS = {0, 4, 8};
    private static final int VISIBILITY_MODE = 78;
    public static final int VISIBILITY_MODE_IGNORE = 1;
    public static final int VISIBILITY_MODE_NORMAL = 0;
    public static final int VISIBLE = 0;
    private static final int WIDTH_DEFAULT = 54;
    private static final int WIDTH_MAX = 56;
    private static final int WIDTH_MIN = 58;
    private static final int WIDTH_PERCENT = 69;
    public static final int WRAP_CONTENT = -2;
    private static SparseIntArray mapToConstant;
    private boolean mValidate;
    private HashMap<String, ConstraintAttribute> mSavedAttributes = new HashMap<>();
    private boolean mForceId = true;
    private HashMap<Integer, Constraint> mConstraints = new HashMap<>();

    public static class Constraint {
        public int mViewId;
        public final PropertySet propertySet = new PropertySet();
        public final Motion motion = new Motion();
        public final Layout layout = new Layout();
        public final Transform transform = new Transform();
        public HashMap<String, ConstraintAttribute> mCustomConstraints = new HashMap<>();

        /* JADX INFO: Access modifiers changed from: private */
        public void fillFrom(int i2, ConstraintLayout.LayoutParams layoutParams) {
            this.mViewId = i2;
            Layout layout = this.layout;
            layout.leftToLeft = layoutParams.leftToLeft;
            layout.leftToRight = layoutParams.leftToRight;
            layout.rightToLeft = layoutParams.rightToLeft;
            layout.rightToRight = layoutParams.rightToRight;
            layout.topToTop = layoutParams.topToTop;
            layout.topToBottom = layoutParams.topToBottom;
            layout.bottomToTop = layoutParams.bottomToTop;
            layout.bottomToBottom = layoutParams.bottomToBottom;
            layout.baselineToBaseline = layoutParams.baselineToBaseline;
            layout.startToEnd = layoutParams.startToEnd;
            layout.startToStart = layoutParams.startToStart;
            layout.endToStart = layoutParams.endToStart;
            layout.endToEnd = layoutParams.endToEnd;
            layout.horizontalBias = layoutParams.horizontalBias;
            layout.verticalBias = layoutParams.verticalBias;
            layout.dimensionRatio = layoutParams.dimensionRatio;
            layout.circleConstraint = layoutParams.circleConstraint;
            layout.circleRadius = layoutParams.circleRadius;
            layout.circleAngle = layoutParams.circleAngle;
            layout.editorAbsoluteX = layoutParams.editorAbsoluteX;
            layout.editorAbsoluteY = layoutParams.editorAbsoluteY;
            layout.orientation = layoutParams.orientation;
            layout.guidePercent = layoutParams.guidePercent;
            layout.guideBegin = layoutParams.guideBegin;
            layout.guideEnd = layoutParams.guideEnd;
            Layout layout2 = this.layout;
            layout2.mWidth = ((ViewGroup.MarginLayoutParams) layoutParams).width;
            layout2.mHeight = ((ViewGroup.MarginLayoutParams) layoutParams).height;
            layout2.leftMargin = ((ViewGroup.MarginLayoutParams) layoutParams).leftMargin;
            layout2.rightMargin = ((ViewGroup.MarginLayoutParams) layoutParams).rightMargin;
            layout2.topMargin = ((ViewGroup.MarginLayoutParams) layoutParams).topMargin;
            layout2.bottomMargin = ((ViewGroup.MarginLayoutParams) layoutParams).bottomMargin;
            layout2.verticalWeight = layoutParams.verticalWeight;
            layout2.horizontalWeight = layoutParams.horizontalWeight;
            layout2.verticalChainStyle = layoutParams.verticalChainStyle;
            layout2.horizontalChainStyle = layoutParams.horizontalChainStyle;
            layout2.constrainedWidth = layoutParams.constrainedWidth;
            layout2.constrainedHeight = layoutParams.constrainedHeight;
            layout2.widthDefault = layoutParams.matchConstraintDefaultWidth;
            layout2.heightDefault = layoutParams.matchConstraintDefaultHeight;
            layout2.widthMax = layoutParams.matchConstraintMaxWidth;
            layout2.heightMax = layoutParams.matchConstraintMaxHeight;
            layout2.widthMin = layoutParams.matchConstraintMinWidth;
            layout2.heightMin = layoutParams.matchConstraintMinHeight;
            layout2.widthPercent = layoutParams.matchConstraintPercentWidth;
            layout2.heightPercent = layoutParams.matchConstraintPercentHeight;
            layout2.mConstraintTag = layoutParams.constraintTag;
            layout2.goneTopMargin = layoutParams.goneTopMargin;
            layout2.goneBottomMargin = layoutParams.goneBottomMargin;
            layout2.goneLeftMargin = layoutParams.goneLeftMargin;
            layout2.goneRightMargin = layoutParams.goneRightMargin;
            Layout layout3 = this.layout;
            layout3.goneStartMargin = layoutParams.goneStartMargin;
            layout3.goneEndMargin = layoutParams.goneEndMargin;
            layout3.endMargin = layoutParams.getMarginEnd();
            this.layout.startMargin = layoutParams.getMarginStart();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void fillFromConstraints(ConstraintHelper constraintHelper, int i2, Constraints.LayoutParams layoutParams) {
            fillFromConstraints(i2, layoutParams);
            if (constraintHelper instanceof Barrier) {
                Layout layout = this.layout;
                layout.mHelperType = 1;
                Barrier barrier = (Barrier) constraintHelper;
                layout.mBarrierDirection = barrier.getType();
                this.layout.mReferenceIds = barrier.getReferencedIds();
                this.layout.mBarrierMargin = barrier.getMargin();
            }
        }

        private ConstraintAttribute get(String str, ConstraintAttribute.AttributeType attributeType) {
            if (!this.mCustomConstraints.containsKey(str)) {
                ConstraintAttribute constraintAttribute = new ConstraintAttribute(str, attributeType);
                this.mCustomConstraints.put(str, constraintAttribute);
                return constraintAttribute;
            }
            ConstraintAttribute constraintAttribute2 = this.mCustomConstraints.get(str);
            if (constraintAttribute2.getType() == attributeType) {
                return constraintAttribute2;
            }
            StringBuilder m586H = C1499a.m586H("ConstraintAttribute is already a ");
            m586H.append(constraintAttribute2.getType().name());
            throw new IllegalArgumentException(m586H.toString());
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setColorValue(String str, int i2) {
            get(str, ConstraintAttribute.AttributeType.COLOR_TYPE).setColorValue(i2);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setFloatValue(String str, float f2) {
            get(str, ConstraintAttribute.AttributeType.FLOAT_TYPE).setFloatValue(f2);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setIntValue(String str, int i2) {
            get(str, ConstraintAttribute.AttributeType.INT_TYPE).setIntValue(i2);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setStringValue(String str, String str2) {
            get(str, ConstraintAttribute.AttributeType.STRING_TYPE).setStringValue(str2);
        }

        public void applyTo(ConstraintLayout.LayoutParams layoutParams) {
            Layout layout = this.layout;
            layoutParams.leftToLeft = layout.leftToLeft;
            layoutParams.leftToRight = layout.leftToRight;
            layoutParams.rightToLeft = layout.rightToLeft;
            layoutParams.rightToRight = layout.rightToRight;
            layoutParams.topToTop = layout.topToTop;
            layoutParams.topToBottom = layout.topToBottom;
            layoutParams.bottomToTop = layout.bottomToTop;
            layoutParams.bottomToBottom = layout.bottomToBottom;
            layoutParams.baselineToBaseline = layout.baselineToBaseline;
            layoutParams.startToEnd = layout.startToEnd;
            layoutParams.startToStart = layout.startToStart;
            layoutParams.endToStart = layout.endToStart;
            layoutParams.endToEnd = layout.endToEnd;
            ((ViewGroup.MarginLayoutParams) layoutParams).leftMargin = layout.leftMargin;
            ((ViewGroup.MarginLayoutParams) layoutParams).rightMargin = layout.rightMargin;
            ((ViewGroup.MarginLayoutParams) layoutParams).topMargin = layout.topMargin;
            ((ViewGroup.MarginLayoutParams) layoutParams).bottomMargin = layout.bottomMargin;
            layoutParams.goneStartMargin = layout.goneStartMargin;
            layoutParams.goneEndMargin = layout.goneEndMargin;
            layoutParams.goneTopMargin = layout.goneTopMargin;
            layoutParams.goneBottomMargin = layout.goneBottomMargin;
            layoutParams.horizontalBias = layout.horizontalBias;
            layoutParams.verticalBias = layout.verticalBias;
            layoutParams.circleConstraint = layout.circleConstraint;
            layoutParams.circleRadius = layout.circleRadius;
            Layout layout2 = this.layout;
            layoutParams.circleAngle = layout2.circleAngle;
            layoutParams.dimensionRatio = layout2.dimensionRatio;
            layoutParams.editorAbsoluteX = layout2.editorAbsoluteX;
            layoutParams.editorAbsoluteY = layout2.editorAbsoluteY;
            layoutParams.verticalWeight = layout2.verticalWeight;
            layoutParams.horizontalWeight = layout2.horizontalWeight;
            layoutParams.verticalChainStyle = layout2.verticalChainStyle;
            layoutParams.horizontalChainStyle = layout2.horizontalChainStyle;
            layoutParams.constrainedWidth = layout2.constrainedWidth;
            layoutParams.constrainedHeight = layout2.constrainedHeight;
            layoutParams.matchConstraintDefaultWidth = layout2.widthDefault;
            layoutParams.matchConstraintDefaultHeight = layout2.heightDefault;
            layoutParams.matchConstraintMaxWidth = layout2.widthMax;
            layoutParams.matchConstraintMaxHeight = layout2.heightMax;
            layoutParams.matchConstraintMinWidth = layout2.widthMin;
            layoutParams.matchConstraintMinHeight = layout2.heightMin;
            layoutParams.matchConstraintPercentWidth = layout2.widthPercent;
            layoutParams.matchConstraintPercentHeight = layout2.heightPercent;
            layoutParams.orientation = layout2.orientation;
            layoutParams.guidePercent = layout2.guidePercent;
            layoutParams.guideBegin = layout2.guideBegin;
            layoutParams.guideEnd = layout2.guideEnd;
            ((ViewGroup.MarginLayoutParams) layoutParams).width = layout2.mWidth;
            ((ViewGroup.MarginLayoutParams) layoutParams).height = layout2.mHeight;
            String str = layout2.mConstraintTag;
            if (str != null) {
                layoutParams.constraintTag = str;
            }
            layoutParams.setMarginStart(this.layout.startMargin);
            layoutParams.setMarginEnd(this.layout.endMargin);
            layoutParams.validate();
        }

        /* renamed from: clone, reason: merged with bridge method [inline-methods] */
        public Constraint m5727clone() {
            Constraint constraint = new Constraint();
            constraint.layout.copyFrom(this.layout);
            constraint.motion.copyFrom(this.motion);
            constraint.propertySet.copyFrom(this.propertySet);
            constraint.transform.copyFrom(this.transform);
            constraint.mViewId = this.mViewId;
            return constraint;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void fillFromConstraints(int i2, Constraints.LayoutParams layoutParams) {
            fillFrom(i2, layoutParams);
            this.propertySet.alpha = layoutParams.alpha;
            Transform transform = this.transform;
            transform.rotation = layoutParams.rotation;
            transform.rotationX = layoutParams.rotationX;
            transform.rotationY = layoutParams.rotationY;
            transform.scaleX = layoutParams.scaleX;
            transform.scaleY = layoutParams.scaleY;
            transform.transformPivotX = layoutParams.transformPivotX;
            transform.transformPivotY = layoutParams.transformPivotY;
            transform.translationX = layoutParams.translationX;
            transform.translationY = layoutParams.translationY;
            transform.translationZ = layoutParams.translationZ;
            transform.elevation = layoutParams.elevation;
            transform.applyElevation = layoutParams.applyElevation;
        }
    }

    public static class Layout {
        private static final int BARRIER_ALLOWS_GONE_WIDGETS = 75;
        private static final int BARRIER_DIRECTION = 72;
        private static final int BARRIER_MARGIN = 73;
        private static final int BASELINE_TO_BASELINE = 1;
        private static final int BOTTOM_MARGIN = 2;
        private static final int BOTTOM_TO_BOTTOM = 3;
        private static final int BOTTOM_TO_TOP = 4;
        private static final int CHAIN_USE_RTL = 71;
        private static final int CIRCLE = 61;
        private static final int CIRCLE_ANGLE = 63;
        private static final int CIRCLE_RADIUS = 62;
        private static final int CONSTRAINT_REFERENCED_IDS = 74;
        private static final int DIMENSION_RATIO = 5;
        private static final int EDITOR_ABSOLUTE_X = 6;
        private static final int EDITOR_ABSOLUTE_Y = 7;
        private static final int END_MARGIN = 8;
        private static final int END_TO_END = 9;
        private static final int END_TO_START = 10;
        private static final int GONE_BOTTOM_MARGIN = 11;
        private static final int GONE_END_MARGIN = 12;
        private static final int GONE_LEFT_MARGIN = 13;
        private static final int GONE_RIGHT_MARGIN = 14;
        private static final int GONE_START_MARGIN = 15;
        private static final int GONE_TOP_MARGIN = 16;
        private static final int GUIDE_BEGIN = 17;
        private static final int GUIDE_END = 18;
        private static final int GUIDE_PERCENT = 19;
        private static final int HEIGHT_PERCENT = 70;
        private static final int HORIZONTAL_BIAS = 20;
        private static final int HORIZONTAL_STYLE = 39;
        private static final int HORIZONTAL_WEIGHT = 37;
        private static final int LAYOUT_HEIGHT = 21;
        private static final int LAYOUT_WIDTH = 22;
        private static final int LEFT_MARGIN = 23;
        private static final int LEFT_TO_LEFT = 24;
        private static final int LEFT_TO_RIGHT = 25;
        private static final int ORIENTATION = 26;
        private static final int RIGHT_MARGIN = 27;
        private static final int RIGHT_TO_LEFT = 28;
        private static final int RIGHT_TO_RIGHT = 29;
        private static final int START_MARGIN = 30;
        private static final int START_TO_END = 31;
        private static final int START_TO_START = 32;
        private static final int TOP_MARGIN = 33;
        private static final int TOP_TO_BOTTOM = 34;
        private static final int TOP_TO_TOP = 35;
        public static final int UNSET = -1;
        private static final int UNUSED = 76;
        private static final int VERTICAL_BIAS = 36;
        private static final int VERTICAL_STYLE = 40;
        private static final int VERTICAL_WEIGHT = 38;
        private static final int WIDTH_PERCENT = 69;
        private static SparseIntArray mapToConstant;
        public String mConstraintTag;
        public int mHeight;
        public String mReferenceIdString;
        public int[] mReferenceIds;
        public int mWidth;
        public boolean mIsGuideline = false;
        public boolean mApply = false;
        public int guideBegin = -1;
        public int guideEnd = -1;
        public float guidePercent = -1.0f;
        public int leftToLeft = -1;
        public int leftToRight = -1;
        public int rightToLeft = -1;
        public int rightToRight = -1;
        public int topToTop = -1;
        public int topToBottom = -1;
        public int bottomToTop = -1;
        public int bottomToBottom = -1;
        public int baselineToBaseline = -1;
        public int startToEnd = -1;
        public int startToStart = -1;
        public int endToStart = -1;
        public int endToEnd = -1;
        public float horizontalBias = 0.5f;
        public float verticalBias = 0.5f;
        public String dimensionRatio = null;
        public int circleConstraint = -1;
        public int circleRadius = 0;
        public float circleAngle = 0.0f;
        public int editorAbsoluteX = -1;
        public int editorAbsoluteY = -1;
        public int orientation = -1;
        public int leftMargin = -1;
        public int rightMargin = -1;
        public int topMargin = -1;
        public int bottomMargin = -1;
        public int endMargin = -1;
        public int startMargin = -1;
        public int goneLeftMargin = -1;
        public int goneTopMargin = -1;
        public int goneRightMargin = -1;
        public int goneBottomMargin = -1;
        public int goneEndMargin = -1;
        public int goneStartMargin = -1;
        public float verticalWeight = -1.0f;
        public float horizontalWeight = -1.0f;
        public int horizontalChainStyle = 0;
        public int verticalChainStyle = 0;
        public int widthDefault = 0;
        public int heightDefault = 0;
        public int widthMax = -1;
        public int heightMax = -1;
        public int widthMin = -1;
        public int heightMin = -1;
        public float widthPercent = 1.0f;
        public float heightPercent = 1.0f;
        public int mBarrierDirection = -1;
        public int mBarrierMargin = 0;
        public int mHelperType = -1;
        public boolean constrainedWidth = false;
        public boolean constrainedHeight = false;
        public boolean mBarrierAllowsGoneWidgets = true;

        static {
            SparseIntArray sparseIntArray = new SparseIntArray();
            mapToConstant = sparseIntArray;
            sparseIntArray.append(C0257R.styleable.Layout_layout_constraintLeft_toLeftOf, 24);
            mapToConstant.append(C0257R.styleable.Layout_layout_constraintLeft_toRightOf, 25);
            mapToConstant.append(C0257R.styleable.Layout_layout_constraintRight_toLeftOf, 28);
            mapToConstant.append(C0257R.styleable.Layout_layout_constraintRight_toRightOf, 29);
            mapToConstant.append(C0257R.styleable.Layout_layout_constraintTop_toTopOf, 35);
            mapToConstant.append(C0257R.styleable.Layout_layout_constraintTop_toBottomOf, 34);
            mapToConstant.append(C0257R.styleable.Layout_layout_constraintBottom_toTopOf, 4);
            mapToConstant.append(C0257R.styleable.Layout_layout_constraintBottom_toBottomOf, 3);
            mapToConstant.append(C0257R.styleable.Layout_layout_constraintBaseline_toBaselineOf, 1);
            mapToConstant.append(C0257R.styleable.Layout_layout_editor_absoluteX, 6);
            mapToConstant.append(C0257R.styleable.Layout_layout_editor_absoluteY, 7);
            mapToConstant.append(C0257R.styleable.Layout_layout_constraintGuide_begin, 17);
            mapToConstant.append(C0257R.styleable.Layout_layout_constraintGuide_end, 18);
            mapToConstant.append(C0257R.styleable.Layout_layout_constraintGuide_percent, 19);
            mapToConstant.append(C0257R.styleable.Layout_android_orientation, 26);
            mapToConstant.append(C0257R.styleable.Layout_layout_constraintStart_toEndOf, 31);
            mapToConstant.append(C0257R.styleable.Layout_layout_constraintStart_toStartOf, 32);
            mapToConstant.append(C0257R.styleable.Layout_layout_constraintEnd_toStartOf, 10);
            mapToConstant.append(C0257R.styleable.Layout_layout_constraintEnd_toEndOf, 9);
            mapToConstant.append(C0257R.styleable.Layout_layout_goneMarginLeft, 13);
            mapToConstant.append(C0257R.styleable.Layout_layout_goneMarginTop, 16);
            mapToConstant.append(C0257R.styleable.Layout_layout_goneMarginRight, 14);
            mapToConstant.append(C0257R.styleable.Layout_layout_goneMarginBottom, 11);
            mapToConstant.append(C0257R.styleable.Layout_layout_goneMarginStart, 15);
            mapToConstant.append(C0257R.styleable.Layout_layout_goneMarginEnd, 12);
            mapToConstant.append(C0257R.styleable.Layout_layout_constraintVertical_weight, 38);
            mapToConstant.append(C0257R.styleable.Layout_layout_constraintHorizontal_weight, 37);
            mapToConstant.append(C0257R.styleable.Layout_layout_constraintHorizontal_chainStyle, 39);
            mapToConstant.append(C0257R.styleable.Layout_layout_constraintVertical_chainStyle, 40);
            mapToConstant.append(C0257R.styleable.Layout_layout_constraintHorizontal_bias, 20);
            mapToConstant.append(C0257R.styleable.Layout_layout_constraintVertical_bias, 36);
            mapToConstant.append(C0257R.styleable.Layout_layout_constraintDimensionRatio, 5);
            mapToConstant.append(C0257R.styleable.Layout_layout_constraintLeft_creator, 76);
            mapToConstant.append(C0257R.styleable.Layout_layout_constraintTop_creator, 76);
            mapToConstant.append(C0257R.styleable.Layout_layout_constraintRight_creator, 76);
            mapToConstant.append(C0257R.styleable.Layout_layout_constraintBottom_creator, 76);
            mapToConstant.append(C0257R.styleable.Layout_layout_constraintBaseline_creator, 76);
            mapToConstant.append(C0257R.styleable.Layout_android_layout_marginLeft, 23);
            mapToConstant.append(C0257R.styleable.Layout_android_layout_marginRight, 27);
            mapToConstant.append(C0257R.styleable.Layout_android_layout_marginStart, 30);
            mapToConstant.append(C0257R.styleable.Layout_android_layout_marginEnd, 8);
            mapToConstant.append(C0257R.styleable.Layout_android_layout_marginTop, 33);
            mapToConstant.append(C0257R.styleable.Layout_android_layout_marginBottom, 2);
            mapToConstant.append(C0257R.styleable.Layout_android_layout_width, 22);
            mapToConstant.append(C0257R.styleable.Layout_android_layout_height, 21);
            mapToConstant.append(C0257R.styleable.Layout_layout_constraintCircle, 61);
            mapToConstant.append(C0257R.styleable.Layout_layout_constraintCircleRadius, 62);
            mapToConstant.append(C0257R.styleable.Layout_layout_constraintCircleAngle, 63);
            mapToConstant.append(C0257R.styleable.Layout_layout_constraintWidth_percent, 69);
            mapToConstant.append(C0257R.styleable.Layout_layout_constraintHeight_percent, 70);
            mapToConstant.append(C0257R.styleable.Layout_chainUseRtl, 71);
            mapToConstant.append(C0257R.styleable.Layout_barrierDirection, 72);
            mapToConstant.append(C0257R.styleable.Layout_barrierMargin, 73);
            mapToConstant.append(C0257R.styleable.Layout_constraint_referenced_ids, 74);
            mapToConstant.append(C0257R.styleable.Layout_barrierAllowsGoneWidgets, 75);
        }

        public void copyFrom(Layout layout) {
            this.mIsGuideline = layout.mIsGuideline;
            this.mWidth = layout.mWidth;
            this.mApply = layout.mApply;
            this.mHeight = layout.mHeight;
            this.guideBegin = layout.guideBegin;
            this.guideEnd = layout.guideEnd;
            this.guidePercent = layout.guidePercent;
            this.leftToLeft = layout.leftToLeft;
            this.leftToRight = layout.leftToRight;
            this.rightToLeft = layout.rightToLeft;
            this.rightToRight = layout.rightToRight;
            this.topToTop = layout.topToTop;
            this.topToBottom = layout.topToBottom;
            this.bottomToTop = layout.bottomToTop;
            this.bottomToBottom = layout.bottomToBottom;
            this.baselineToBaseline = layout.baselineToBaseline;
            this.startToEnd = layout.startToEnd;
            this.startToStart = layout.startToStart;
            this.endToStart = layout.endToStart;
            this.endToEnd = layout.endToEnd;
            this.horizontalBias = layout.horizontalBias;
            this.verticalBias = layout.verticalBias;
            this.dimensionRatio = layout.dimensionRatio;
            this.circleConstraint = layout.circleConstraint;
            this.circleRadius = layout.circleRadius;
            this.circleAngle = layout.circleAngle;
            this.editorAbsoluteX = layout.editorAbsoluteX;
            this.editorAbsoluteY = layout.editorAbsoluteY;
            this.orientation = layout.orientation;
            this.leftMargin = layout.leftMargin;
            this.rightMargin = layout.rightMargin;
            this.topMargin = layout.topMargin;
            this.bottomMargin = layout.bottomMargin;
            this.endMargin = layout.endMargin;
            this.startMargin = layout.startMargin;
            this.goneLeftMargin = layout.goneLeftMargin;
            this.goneTopMargin = layout.goneTopMargin;
            this.goneRightMargin = layout.goneRightMargin;
            this.goneBottomMargin = layout.goneBottomMargin;
            this.goneEndMargin = layout.goneEndMargin;
            this.goneStartMargin = layout.goneStartMargin;
            this.verticalWeight = layout.verticalWeight;
            this.horizontalWeight = layout.horizontalWeight;
            this.horizontalChainStyle = layout.horizontalChainStyle;
            this.verticalChainStyle = layout.verticalChainStyle;
            this.widthDefault = layout.widthDefault;
            this.heightDefault = layout.heightDefault;
            this.widthMax = layout.widthMax;
            this.heightMax = layout.heightMax;
            this.widthMin = layout.widthMin;
            this.heightMin = layout.heightMin;
            this.widthPercent = layout.widthPercent;
            this.heightPercent = layout.heightPercent;
            this.mBarrierDirection = layout.mBarrierDirection;
            this.mBarrierMargin = layout.mBarrierMargin;
            this.mHelperType = layout.mHelperType;
            this.mConstraintTag = layout.mConstraintTag;
            int[] iArr = layout.mReferenceIds;
            if (iArr != null) {
                this.mReferenceIds = Arrays.copyOf(iArr, iArr.length);
            } else {
                this.mReferenceIds = null;
            }
            this.mReferenceIdString = layout.mReferenceIdString;
            this.constrainedWidth = layout.constrainedWidth;
            this.constrainedHeight = layout.constrainedHeight;
            this.mBarrierAllowsGoneWidgets = layout.mBarrierAllowsGoneWidgets;
        }

        public void dump(MotionScene motionScene, StringBuilder sb) {
            Field[] declaredFields = getClass().getDeclaredFields();
            sb.append("\n");
            for (Field field : declaredFields) {
                String name = field.getName();
                if (!Modifier.isStatic(field.getModifiers())) {
                    try {
                        Object obj = field.get(this);
                        Class<?> type = field.getType();
                        if (type == Integer.TYPE) {
                            Integer num = (Integer) obj;
                            if (num.intValue() != -1) {
                                Object lookUpConstraintName = motionScene.lookUpConstraintName(num.intValue());
                                sb.append("    ");
                                sb.append(name);
                                sb.append(" = \"");
                                sb.append(lookUpConstraintName == null ? num : lookUpConstraintName);
                                sb.append("\"\n");
                            }
                        } else if (type == Float.TYPE) {
                            Float f2 = (Float) obj;
                            if (f2.floatValue() != -1.0f) {
                                sb.append("    ");
                                sb.append(name);
                                sb.append(" = \"");
                                sb.append(f2);
                                sb.append("\"\n");
                            }
                        }
                    } catch (IllegalAccessException e2) {
                        e2.printStackTrace();
                    }
                }
            }
        }

        public void fillFromAttributeList(Context context, AttributeSet attributeSet) {
            TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, C0257R.styleable.Layout);
            this.mApply = true;
            int indexCount = obtainStyledAttributes.getIndexCount();
            for (int i2 = 0; i2 < indexCount; i2++) {
                int index = obtainStyledAttributes.getIndex(i2);
                int i3 = mapToConstant.get(index);
                if (i3 == 80) {
                    this.constrainedWidth = obtainStyledAttributes.getBoolean(index, this.constrainedWidth);
                } else if (i3 != 81) {
                    switch (i3) {
                        case 1:
                            this.baselineToBaseline = ConstraintSet.lookupID(obtainStyledAttributes, index, this.baselineToBaseline);
                            break;
                        case 2:
                            this.bottomMargin = obtainStyledAttributes.getDimensionPixelSize(index, this.bottomMargin);
                            break;
                        case 3:
                            this.bottomToBottom = ConstraintSet.lookupID(obtainStyledAttributes, index, this.bottomToBottom);
                            break;
                        case 4:
                            this.bottomToTop = ConstraintSet.lookupID(obtainStyledAttributes, index, this.bottomToTop);
                            break;
                        case 5:
                            this.dimensionRatio = obtainStyledAttributes.getString(index);
                            break;
                        case 6:
                            this.editorAbsoluteX = obtainStyledAttributes.getDimensionPixelOffset(index, this.editorAbsoluteX);
                            break;
                        case 7:
                            this.editorAbsoluteY = obtainStyledAttributes.getDimensionPixelOffset(index, this.editorAbsoluteY);
                            break;
                        case 8:
                            this.endMargin = obtainStyledAttributes.getDimensionPixelSize(index, this.endMargin);
                            break;
                        case 9:
                            this.endToEnd = ConstraintSet.lookupID(obtainStyledAttributes, index, this.endToEnd);
                            break;
                        case 10:
                            this.endToStart = ConstraintSet.lookupID(obtainStyledAttributes, index, this.endToStart);
                            break;
                        case 11:
                            this.goneBottomMargin = obtainStyledAttributes.getDimensionPixelSize(index, this.goneBottomMargin);
                            break;
                        case 12:
                            this.goneEndMargin = obtainStyledAttributes.getDimensionPixelSize(index, this.goneEndMargin);
                            break;
                        case 13:
                            this.goneLeftMargin = obtainStyledAttributes.getDimensionPixelSize(index, this.goneLeftMargin);
                            break;
                        case 14:
                            this.goneRightMargin = obtainStyledAttributes.getDimensionPixelSize(index, this.goneRightMargin);
                            break;
                        case 15:
                            this.goneStartMargin = obtainStyledAttributes.getDimensionPixelSize(index, this.goneStartMargin);
                            break;
                        case 16:
                            this.goneTopMargin = obtainStyledAttributes.getDimensionPixelSize(index, this.goneTopMargin);
                            break;
                        case 17:
                            this.guideBegin = obtainStyledAttributes.getDimensionPixelOffset(index, this.guideBegin);
                            break;
                        case 18:
                            this.guideEnd = obtainStyledAttributes.getDimensionPixelOffset(index, this.guideEnd);
                            break;
                        case 19:
                            this.guidePercent = obtainStyledAttributes.getFloat(index, this.guidePercent);
                            break;
                        case 20:
                            this.horizontalBias = obtainStyledAttributes.getFloat(index, this.horizontalBias);
                            break;
                        case 21:
                            this.mHeight = obtainStyledAttributes.getLayoutDimension(index, this.mHeight);
                            break;
                        case 22:
                            this.mWidth = obtainStyledAttributes.getLayoutDimension(index, this.mWidth);
                            break;
                        case 23:
                            this.leftMargin = obtainStyledAttributes.getDimensionPixelSize(index, this.leftMargin);
                            break;
                        case 24:
                            this.leftToLeft = ConstraintSet.lookupID(obtainStyledAttributes, index, this.leftToLeft);
                            break;
                        case 25:
                            this.leftToRight = ConstraintSet.lookupID(obtainStyledAttributes, index, this.leftToRight);
                            break;
                        case 26:
                            this.orientation = obtainStyledAttributes.getInt(index, this.orientation);
                            break;
                        case 27:
                            this.rightMargin = obtainStyledAttributes.getDimensionPixelSize(index, this.rightMargin);
                            break;
                        case 28:
                            this.rightToLeft = ConstraintSet.lookupID(obtainStyledAttributes, index, this.rightToLeft);
                            break;
                        case 29:
                            this.rightToRight = ConstraintSet.lookupID(obtainStyledAttributes, index, this.rightToRight);
                            break;
                        case 30:
                            this.startMargin = obtainStyledAttributes.getDimensionPixelSize(index, this.startMargin);
                            break;
                        case 31:
                            this.startToEnd = ConstraintSet.lookupID(obtainStyledAttributes, index, this.startToEnd);
                            break;
                        case 32:
                            this.startToStart = ConstraintSet.lookupID(obtainStyledAttributes, index, this.startToStart);
                            break;
                        case 33:
                            this.topMargin = obtainStyledAttributes.getDimensionPixelSize(index, this.topMargin);
                            break;
                        case 34:
                            this.topToBottom = ConstraintSet.lookupID(obtainStyledAttributes, index, this.topToBottom);
                            break;
                        case 35:
                            this.topToTop = ConstraintSet.lookupID(obtainStyledAttributes, index, this.topToTop);
                            break;
                        case 36:
                            this.verticalBias = obtainStyledAttributes.getFloat(index, this.verticalBias);
                            break;
                        case 37:
                            this.horizontalWeight = obtainStyledAttributes.getFloat(index, this.horizontalWeight);
                            break;
                        case 38:
                            this.verticalWeight = obtainStyledAttributes.getFloat(index, this.verticalWeight);
                            break;
                        case 39:
                            this.horizontalChainStyle = obtainStyledAttributes.getInt(index, this.horizontalChainStyle);
                            break;
                        case 40:
                            this.verticalChainStyle = obtainStyledAttributes.getInt(index, this.verticalChainStyle);
                            break;
                        default:
                            switch (i3) {
                                case 54:
                                    this.widthDefault = obtainStyledAttributes.getInt(index, this.widthDefault);
                                    break;
                                case 55:
                                    this.heightDefault = obtainStyledAttributes.getInt(index, this.heightDefault);
                                    break;
                                case 56:
                                    this.widthMax = obtainStyledAttributes.getDimensionPixelSize(index, this.widthMax);
                                    break;
                                case 57:
                                    this.heightMax = obtainStyledAttributes.getDimensionPixelSize(index, this.heightMax);
                                    break;
                                case 58:
                                    this.widthMin = obtainStyledAttributes.getDimensionPixelSize(index, this.widthMin);
                                    break;
                                case 59:
                                    this.heightMin = obtainStyledAttributes.getDimensionPixelSize(index, this.heightMin);
                                    break;
                                default:
                                    switch (i3) {
                                        case 61:
                                            this.circleConstraint = ConstraintSet.lookupID(obtainStyledAttributes, index, this.circleConstraint);
                                            break;
                                        case 62:
                                            this.circleRadius = obtainStyledAttributes.getDimensionPixelSize(index, this.circleRadius);
                                            break;
                                        case 63:
                                            this.circleAngle = obtainStyledAttributes.getFloat(index, this.circleAngle);
                                            break;
                                        default:
                                            switch (i3) {
                                                case 69:
                                                    this.widthPercent = obtainStyledAttributes.getFloat(index, 1.0f);
                                                    break;
                                                case 70:
                                                    this.heightPercent = obtainStyledAttributes.getFloat(index, 1.0f);
                                                    break;
                                                case 71:
                                                    break;
                                                case 72:
                                                    this.mBarrierDirection = obtainStyledAttributes.getInt(index, this.mBarrierDirection);
                                                    break;
                                                case 73:
                                                    this.mBarrierMargin = obtainStyledAttributes.getDimensionPixelSize(index, this.mBarrierMargin);
                                                    break;
                                                case 74:
                                                    this.mReferenceIdString = obtainStyledAttributes.getString(index);
                                                    break;
                                                case 75:
                                                    this.mBarrierAllowsGoneWidgets = obtainStyledAttributes.getBoolean(index, this.mBarrierAllowsGoneWidgets);
                                                    break;
                                                case 76:
                                                    Integer.toHexString(index);
                                                    mapToConstant.get(index);
                                                    break;
                                                case 77:
                                                    this.mConstraintTag = obtainStyledAttributes.getString(index);
                                                    break;
                                                default:
                                                    Integer.toHexString(index);
                                                    mapToConstant.get(index);
                                                    break;
                                            }
                                    }
                            }
                    }
                } else {
                    this.constrainedHeight = obtainStyledAttributes.getBoolean(index, this.constrainedHeight);
                }
            }
            obtainStyledAttributes.recycle();
        }
    }

    public static class Motion {
        private static final int ANIMATE_RELATIVE_TO = 5;
        private static final int MOTION_DRAW_PATH = 4;
        private static final int MOTION_STAGGER = 6;
        private static final int PATH_MOTION_ARC = 2;
        private static final int TRANSITION_EASING = 3;
        private static final int TRANSITION_PATH_ROTATE = 1;
        private static SparseIntArray mapToConstant;
        public boolean mApply = false;
        public int mAnimateRelativeTo = -1;
        public String mTransitionEasing = null;
        public int mPathMotionArc = -1;
        public int mDrawPath = 0;
        public float mMotionStagger = Float.NaN;
        public float mPathRotate = Float.NaN;

        static {
            SparseIntArray sparseIntArray = new SparseIntArray();
            mapToConstant = sparseIntArray;
            sparseIntArray.append(C0257R.styleable.Motion_motionPathRotate, 1);
            mapToConstant.append(C0257R.styleable.Motion_pathMotionArc, 2);
            mapToConstant.append(C0257R.styleable.Motion_transitionEasing, 3);
            mapToConstant.append(C0257R.styleable.Motion_drawPath, 4);
            mapToConstant.append(C0257R.styleable.Motion_animate_relativeTo, 5);
            mapToConstant.append(C0257R.styleable.Motion_motionStagger, 6);
        }

        public void copyFrom(Motion motion) {
            this.mApply = motion.mApply;
            this.mAnimateRelativeTo = motion.mAnimateRelativeTo;
            this.mTransitionEasing = motion.mTransitionEasing;
            this.mPathMotionArc = motion.mPathMotionArc;
            this.mDrawPath = motion.mDrawPath;
            this.mPathRotate = motion.mPathRotate;
            this.mMotionStagger = motion.mMotionStagger;
        }

        public void fillFromAttributeList(Context context, AttributeSet attributeSet) {
            TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, C0257R.styleable.Motion);
            this.mApply = true;
            int indexCount = obtainStyledAttributes.getIndexCount();
            for (int i2 = 0; i2 < indexCount; i2++) {
                int index = obtainStyledAttributes.getIndex(i2);
                switch (mapToConstant.get(index)) {
                    case 1:
                        this.mPathRotate = obtainStyledAttributes.getFloat(index, this.mPathRotate);
                        break;
                    case 2:
                        this.mPathMotionArc = obtainStyledAttributes.getInt(index, this.mPathMotionArc);
                        break;
                    case 3:
                        if (obtainStyledAttributes.peekValue(index).type == 3) {
                            this.mTransitionEasing = obtainStyledAttributes.getString(index);
                            break;
                        } else {
                            this.mTransitionEasing = Easing.NAMED_EASING[obtainStyledAttributes.getInteger(index, 0)];
                            break;
                        }
                    case 4:
                        this.mDrawPath = obtainStyledAttributes.getInt(index, 0);
                        break;
                    case 5:
                        this.mAnimateRelativeTo = ConstraintSet.lookupID(obtainStyledAttributes, index, this.mAnimateRelativeTo);
                        break;
                    case 6:
                        this.mMotionStagger = obtainStyledAttributes.getFloat(index, this.mMotionStagger);
                        break;
                }
            }
            obtainStyledAttributes.recycle();
        }
    }

    public static class PropertySet {
        public boolean mApply = false;
        public int visibility = 0;
        public int mVisibilityMode = 0;
        public float alpha = 1.0f;
        public float mProgress = Float.NaN;

        public void copyFrom(PropertySet propertySet) {
            this.mApply = propertySet.mApply;
            this.visibility = propertySet.visibility;
            this.alpha = propertySet.alpha;
            this.mProgress = propertySet.mProgress;
            this.mVisibilityMode = propertySet.mVisibilityMode;
        }

        public void fillFromAttributeList(Context context, AttributeSet attributeSet) {
            TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, C0257R.styleable.PropertySet);
            this.mApply = true;
            int indexCount = obtainStyledAttributes.getIndexCount();
            for (int i2 = 0; i2 < indexCount; i2++) {
                int index = obtainStyledAttributes.getIndex(i2);
                if (index == C0257R.styleable.PropertySet_android_alpha) {
                    this.alpha = obtainStyledAttributes.getFloat(index, this.alpha);
                } else if (index == C0257R.styleable.PropertySet_android_visibility) {
                    this.visibility = obtainStyledAttributes.getInt(index, this.visibility);
                    this.visibility = ConstraintSet.VISIBILITY_FLAGS[this.visibility];
                } else if (index == C0257R.styleable.PropertySet_visibilityMode) {
                    this.mVisibilityMode = obtainStyledAttributes.getInt(index, this.mVisibilityMode);
                } else if (index == C0257R.styleable.PropertySet_motionProgress) {
                    this.mProgress = obtainStyledAttributes.getFloat(index, this.mProgress);
                }
            }
            obtainStyledAttributes.recycle();
        }
    }

    public static class Transform {
        private static final int ELEVATION = 11;
        private static final int ROTATION = 1;
        private static final int ROTATION_X = 2;
        private static final int ROTATION_Y = 3;
        private static final int SCALE_X = 4;
        private static final int SCALE_Y = 5;
        private static final int TRANSFORM_PIVOT_X = 6;
        private static final int TRANSFORM_PIVOT_Y = 7;
        private static final int TRANSLATION_X = 8;
        private static final int TRANSLATION_Y = 9;
        private static final int TRANSLATION_Z = 10;
        private static SparseIntArray mapToConstant;
        public boolean mApply = false;
        public float rotation = 0.0f;
        public float rotationX = 0.0f;
        public float rotationY = 0.0f;
        public float scaleX = 1.0f;
        public float scaleY = 1.0f;
        public float transformPivotX = Float.NaN;
        public float transformPivotY = Float.NaN;
        public float translationX = 0.0f;
        public float translationY = 0.0f;
        public float translationZ = 0.0f;
        public boolean applyElevation = false;
        public float elevation = 0.0f;

        static {
            SparseIntArray sparseIntArray = new SparseIntArray();
            mapToConstant = sparseIntArray;
            sparseIntArray.append(C0257R.styleable.Transform_android_rotation, 1);
            mapToConstant.append(C0257R.styleable.Transform_android_rotationX, 2);
            mapToConstant.append(C0257R.styleable.Transform_android_rotationY, 3);
            mapToConstant.append(C0257R.styleable.Transform_android_scaleX, 4);
            mapToConstant.append(C0257R.styleable.Transform_android_scaleY, 5);
            mapToConstant.append(C0257R.styleable.Transform_android_transformPivotX, 6);
            mapToConstant.append(C0257R.styleable.Transform_android_transformPivotY, 7);
            mapToConstant.append(C0257R.styleable.Transform_android_translationX, 8);
            mapToConstant.append(C0257R.styleable.Transform_android_translationY, 9);
            mapToConstant.append(C0257R.styleable.Transform_android_translationZ, 10);
            mapToConstant.append(C0257R.styleable.Transform_android_elevation, 11);
        }

        public void copyFrom(Transform transform) {
            this.mApply = transform.mApply;
            this.rotation = transform.rotation;
            this.rotationX = transform.rotationX;
            this.rotationY = transform.rotationY;
            this.scaleX = transform.scaleX;
            this.scaleY = transform.scaleY;
            this.transformPivotX = transform.transformPivotX;
            this.transformPivotY = transform.transformPivotY;
            this.translationX = transform.translationX;
            this.translationY = transform.translationY;
            this.translationZ = transform.translationZ;
            this.applyElevation = transform.applyElevation;
            this.elevation = transform.elevation;
        }

        public void fillFromAttributeList(Context context, AttributeSet attributeSet) {
            TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, C0257R.styleable.Transform);
            this.mApply = true;
            int indexCount = obtainStyledAttributes.getIndexCount();
            for (int i2 = 0; i2 < indexCount; i2++) {
                int index = obtainStyledAttributes.getIndex(i2);
                switch (mapToConstant.get(index)) {
                    case 1:
                        this.rotation = obtainStyledAttributes.getFloat(index, this.rotation);
                        break;
                    case 2:
                        this.rotationX = obtainStyledAttributes.getFloat(index, this.rotationX);
                        break;
                    case 3:
                        this.rotationY = obtainStyledAttributes.getFloat(index, this.rotationY);
                        break;
                    case 4:
                        this.scaleX = obtainStyledAttributes.getFloat(index, this.scaleX);
                        break;
                    case 5:
                        this.scaleY = obtainStyledAttributes.getFloat(index, this.scaleY);
                        break;
                    case 6:
                        this.transformPivotX = obtainStyledAttributes.getDimension(index, this.transformPivotX);
                        break;
                    case 7:
                        this.transformPivotY = obtainStyledAttributes.getDimension(index, this.transformPivotY);
                        break;
                    case 8:
                        this.translationX = obtainStyledAttributes.getDimension(index, this.translationX);
                        break;
                    case 9:
                        this.translationY = obtainStyledAttributes.getDimension(index, this.translationY);
                        break;
                    case 10:
                        this.translationZ = obtainStyledAttributes.getDimension(index, this.translationZ);
                        break;
                    case 11:
                        this.applyElevation = true;
                        this.elevation = obtainStyledAttributes.getDimension(index, this.elevation);
                        break;
                }
            }
            obtainStyledAttributes.recycle();
        }
    }

    static {
        SparseIntArray sparseIntArray = new SparseIntArray();
        mapToConstant = sparseIntArray;
        sparseIntArray.append(C0257R.styleable.Constraint_layout_constraintLeft_toLeftOf, 25);
        mapToConstant.append(C0257R.styleable.Constraint_layout_constraintLeft_toRightOf, 26);
        mapToConstant.append(C0257R.styleable.Constraint_layout_constraintRight_toLeftOf, 29);
        mapToConstant.append(C0257R.styleable.Constraint_layout_constraintRight_toRightOf, 30);
        mapToConstant.append(C0257R.styleable.Constraint_layout_constraintTop_toTopOf, 36);
        mapToConstant.append(C0257R.styleable.Constraint_layout_constraintTop_toBottomOf, 35);
        mapToConstant.append(C0257R.styleable.Constraint_layout_constraintBottom_toTopOf, 4);
        mapToConstant.append(C0257R.styleable.Constraint_layout_constraintBottom_toBottomOf, 3);
        mapToConstant.append(C0257R.styleable.Constraint_layout_constraintBaseline_toBaselineOf, 1);
        mapToConstant.append(C0257R.styleable.Constraint_layout_editor_absoluteX, 6);
        mapToConstant.append(C0257R.styleable.Constraint_layout_editor_absoluteY, 7);
        mapToConstant.append(C0257R.styleable.Constraint_layout_constraintGuide_begin, 17);
        mapToConstant.append(C0257R.styleable.Constraint_layout_constraintGuide_end, 18);
        mapToConstant.append(C0257R.styleable.Constraint_layout_constraintGuide_percent, 19);
        mapToConstant.append(C0257R.styleable.Constraint_android_orientation, 27);
        mapToConstant.append(C0257R.styleable.Constraint_layout_constraintStart_toEndOf, 32);
        mapToConstant.append(C0257R.styleable.Constraint_layout_constraintStart_toStartOf, 33);
        mapToConstant.append(C0257R.styleable.Constraint_layout_constraintEnd_toStartOf, 10);
        mapToConstant.append(C0257R.styleable.Constraint_layout_constraintEnd_toEndOf, 9);
        mapToConstant.append(C0257R.styleable.Constraint_layout_goneMarginLeft, 13);
        mapToConstant.append(C0257R.styleable.Constraint_layout_goneMarginTop, 16);
        mapToConstant.append(C0257R.styleable.Constraint_layout_goneMarginRight, 14);
        mapToConstant.append(C0257R.styleable.Constraint_layout_goneMarginBottom, 11);
        mapToConstant.append(C0257R.styleable.Constraint_layout_goneMarginStart, 15);
        mapToConstant.append(C0257R.styleable.Constraint_layout_goneMarginEnd, 12);
        mapToConstant.append(C0257R.styleable.Constraint_layout_constraintVertical_weight, 40);
        mapToConstant.append(C0257R.styleable.Constraint_layout_constraintHorizontal_weight, 39);
        mapToConstant.append(C0257R.styleable.Constraint_layout_constraintHorizontal_chainStyle, 41);
        mapToConstant.append(C0257R.styleable.Constraint_layout_constraintVertical_chainStyle, 42);
        mapToConstant.append(C0257R.styleable.Constraint_layout_constraintHorizontal_bias, 20);
        mapToConstant.append(C0257R.styleable.Constraint_layout_constraintVertical_bias, 37);
        mapToConstant.append(C0257R.styleable.Constraint_layout_constraintDimensionRatio, 5);
        mapToConstant.append(C0257R.styleable.Constraint_layout_constraintLeft_creator, 82);
        mapToConstant.append(C0257R.styleable.Constraint_layout_constraintTop_creator, 82);
        mapToConstant.append(C0257R.styleable.Constraint_layout_constraintRight_creator, 82);
        mapToConstant.append(C0257R.styleable.Constraint_layout_constraintBottom_creator, 82);
        mapToConstant.append(C0257R.styleable.Constraint_layout_constraintBaseline_creator, 82);
        mapToConstant.append(C0257R.styleable.Constraint_android_layout_marginLeft, 24);
        mapToConstant.append(C0257R.styleable.Constraint_android_layout_marginRight, 28);
        mapToConstant.append(C0257R.styleable.Constraint_android_layout_marginStart, 31);
        mapToConstant.append(C0257R.styleable.Constraint_android_layout_marginEnd, 8);
        mapToConstant.append(C0257R.styleable.Constraint_android_layout_marginTop, 34);
        mapToConstant.append(C0257R.styleable.Constraint_android_layout_marginBottom, 2);
        mapToConstant.append(C0257R.styleable.Constraint_android_layout_width, 23);
        mapToConstant.append(C0257R.styleable.Constraint_android_layout_height, 21);
        mapToConstant.append(C0257R.styleable.Constraint_android_visibility, 22);
        mapToConstant.append(C0257R.styleable.Constraint_android_alpha, 43);
        mapToConstant.append(C0257R.styleable.Constraint_android_elevation, 44);
        mapToConstant.append(C0257R.styleable.Constraint_android_rotationX, 45);
        mapToConstant.append(C0257R.styleable.Constraint_android_rotationY, 46);
        mapToConstant.append(C0257R.styleable.Constraint_android_rotation, 60);
        mapToConstant.append(C0257R.styleable.Constraint_android_scaleX, 47);
        mapToConstant.append(C0257R.styleable.Constraint_android_scaleY, 48);
        mapToConstant.append(C0257R.styleable.Constraint_android_transformPivotX, 49);
        mapToConstant.append(C0257R.styleable.Constraint_android_transformPivotY, 50);
        mapToConstant.append(C0257R.styleable.Constraint_android_translationX, 51);
        mapToConstant.append(C0257R.styleable.Constraint_android_translationY, 52);
        mapToConstant.append(C0257R.styleable.Constraint_android_translationZ, 53);
        mapToConstant.append(C0257R.styleable.Constraint_layout_constraintWidth_default, 54);
        mapToConstant.append(C0257R.styleable.Constraint_layout_constraintHeight_default, 55);
        mapToConstant.append(C0257R.styleable.Constraint_layout_constraintWidth_max, 56);
        mapToConstant.append(C0257R.styleable.Constraint_layout_constraintHeight_max, 57);
        mapToConstant.append(C0257R.styleable.Constraint_layout_constraintWidth_min, 58);
        mapToConstant.append(C0257R.styleable.Constraint_layout_constraintHeight_min, 59);
        mapToConstant.append(C0257R.styleable.Constraint_layout_constraintCircle, 61);
        mapToConstant.append(C0257R.styleable.Constraint_layout_constraintCircleRadius, 62);
        mapToConstant.append(C0257R.styleable.Constraint_layout_constraintCircleAngle, 63);
        mapToConstant.append(C0257R.styleable.Constraint_animate_relativeTo, 64);
        mapToConstant.append(C0257R.styleable.Constraint_transitionEasing, 65);
        mapToConstant.append(C0257R.styleable.Constraint_drawPath, 66);
        mapToConstant.append(C0257R.styleable.Constraint_transitionPathRotate, 67);
        mapToConstant.append(C0257R.styleable.Constraint_motionStagger, 79);
        mapToConstant.append(C0257R.styleable.Constraint_android_id, 38);
        mapToConstant.append(C0257R.styleable.Constraint_motionProgress, 68);
        mapToConstant.append(C0257R.styleable.Constraint_layout_constraintWidth_percent, 69);
        mapToConstant.append(C0257R.styleable.Constraint_layout_constraintHeight_percent, 70);
        mapToConstant.append(C0257R.styleable.Constraint_chainUseRtl, 71);
        mapToConstant.append(C0257R.styleable.Constraint_barrierDirection, 72);
        mapToConstant.append(C0257R.styleable.Constraint_barrierMargin, 73);
        mapToConstant.append(C0257R.styleable.Constraint_constraint_referenced_ids, 74);
        mapToConstant.append(C0257R.styleable.Constraint_barrierAllowsGoneWidgets, 75);
        mapToConstant.append(C0257R.styleable.Constraint_pathMotionArc, 76);
        mapToConstant.append(C0257R.styleable.Constraint_layout_constraintTag, 77);
        mapToConstant.append(C0257R.styleable.Constraint_visibilityMode, 78);
        mapToConstant.append(C0257R.styleable.Constraint_layout_constrainedWidth, 80);
        mapToConstant.append(C0257R.styleable.Constraint_layout_constrainedHeight, 81);
    }

    private void addAttributes(ConstraintAttribute.AttributeType attributeType, String... strArr) {
        for (int i2 = 0; i2 < strArr.length; i2++) {
            if (this.mSavedAttributes.containsKey(strArr[i2])) {
                ConstraintAttribute constraintAttribute = this.mSavedAttributes.get(strArr[i2]);
                if (constraintAttribute.getType() != attributeType) {
                    StringBuilder m586H = C1499a.m586H("ConstraintAttribute is already a ");
                    m586H.append(constraintAttribute.getType().name());
                    throw new IllegalArgumentException(m586H.toString());
                }
            } else {
                this.mSavedAttributes.put(strArr[i2], new ConstraintAttribute(strArr[i2], attributeType));
            }
        }
    }

    private int[] convertReferenceString(View view, String str) {
        int i2;
        Object designInformation;
        String[] split = str.split(ChineseToPinyinResource.Field.COMMA);
        Context context = view.getContext();
        int[] iArr = new int[split.length];
        int i3 = 0;
        int i4 = 0;
        while (i3 < split.length) {
            String trim = split[i3].trim();
            try {
                i2 = C0257R.id.class.getField(trim).getInt(null);
            } catch (Exception unused) {
                i2 = 0;
            }
            if (i2 == 0) {
                i2 = context.getResources().getIdentifier(trim, "id", context.getPackageName());
            }
            if (i2 == 0 && view.isInEditMode() && (view.getParent() instanceof ConstraintLayout) && (designInformation = ((ConstraintLayout) view.getParent()).getDesignInformation(0, trim)) != null && (designInformation instanceof Integer)) {
                i2 = ((Integer) designInformation).intValue();
            }
            iArr[i4] = i2;
            i3++;
            i4++;
        }
        return i4 != split.length ? Arrays.copyOf(iArr, i4) : iArr;
    }

    private Constraint fillFromAttributeList(Context context, AttributeSet attributeSet) {
        Constraint constraint = new Constraint();
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, C0257R.styleable.Constraint);
        populateConstraint(context, constraint, obtainStyledAttributes);
        obtainStyledAttributes.recycle();
        return constraint;
    }

    private Constraint get(int i2) {
        if (!this.mConstraints.containsKey(Integer.valueOf(i2))) {
            this.mConstraints.put(Integer.valueOf(i2), new Constraint());
        }
        return this.mConstraints.get(Integer.valueOf(i2));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static int lookupID(TypedArray typedArray, int i2, int i3) {
        int resourceId = typedArray.getResourceId(i2, i3);
        return resourceId == -1 ? typedArray.getInt(i2, -1) : resourceId;
    }

    private void populateConstraint(Context context, Constraint constraint, TypedArray typedArray) {
        int indexCount = typedArray.getIndexCount();
        for (int i2 = 0; i2 < indexCount; i2++) {
            int index = typedArray.getIndex(i2);
            if (index != C0257R.styleable.Constraint_android_id && C0257R.styleable.Constraint_android_layout_marginStart != index && C0257R.styleable.Constraint_android_layout_marginEnd != index) {
                constraint.motion.mApply = true;
                constraint.layout.mApply = true;
                constraint.propertySet.mApply = true;
                constraint.transform.mApply = true;
            }
            switch (mapToConstant.get(index)) {
                case 1:
                    Layout layout = constraint.layout;
                    layout.baselineToBaseline = lookupID(typedArray, index, layout.baselineToBaseline);
                    break;
                case 2:
                    Layout layout2 = constraint.layout;
                    layout2.bottomMargin = typedArray.getDimensionPixelSize(index, layout2.bottomMargin);
                    break;
                case 3:
                    Layout layout3 = constraint.layout;
                    layout3.bottomToBottom = lookupID(typedArray, index, layout3.bottomToBottom);
                    break;
                case 4:
                    Layout layout4 = constraint.layout;
                    layout4.bottomToTop = lookupID(typedArray, index, layout4.bottomToTop);
                    break;
                case 5:
                    constraint.layout.dimensionRatio = typedArray.getString(index);
                    break;
                case 6:
                    Layout layout5 = constraint.layout;
                    layout5.editorAbsoluteX = typedArray.getDimensionPixelOffset(index, layout5.editorAbsoluteX);
                    break;
                case 7:
                    Layout layout6 = constraint.layout;
                    layout6.editorAbsoluteY = typedArray.getDimensionPixelOffset(index, layout6.editorAbsoluteY);
                    break;
                case 8:
                    Layout layout7 = constraint.layout;
                    layout7.endMargin = typedArray.getDimensionPixelSize(index, layout7.endMargin);
                    break;
                case 9:
                    Layout layout8 = constraint.layout;
                    layout8.endToEnd = lookupID(typedArray, index, layout8.endToEnd);
                    break;
                case 10:
                    Layout layout9 = constraint.layout;
                    layout9.endToStart = lookupID(typedArray, index, layout9.endToStart);
                    break;
                case 11:
                    Layout layout10 = constraint.layout;
                    layout10.goneBottomMargin = typedArray.getDimensionPixelSize(index, layout10.goneBottomMargin);
                    break;
                case 12:
                    Layout layout11 = constraint.layout;
                    layout11.goneEndMargin = typedArray.getDimensionPixelSize(index, layout11.goneEndMargin);
                    break;
                case 13:
                    Layout layout12 = constraint.layout;
                    layout12.goneLeftMargin = typedArray.getDimensionPixelSize(index, layout12.goneLeftMargin);
                    break;
                case 14:
                    Layout layout13 = constraint.layout;
                    layout13.goneRightMargin = typedArray.getDimensionPixelSize(index, layout13.goneRightMargin);
                    break;
                case 15:
                    Layout layout14 = constraint.layout;
                    layout14.goneStartMargin = typedArray.getDimensionPixelSize(index, layout14.goneStartMargin);
                    break;
                case 16:
                    Layout layout15 = constraint.layout;
                    layout15.goneTopMargin = typedArray.getDimensionPixelSize(index, layout15.goneTopMargin);
                    break;
                case 17:
                    Layout layout16 = constraint.layout;
                    layout16.guideBegin = typedArray.getDimensionPixelOffset(index, layout16.guideBegin);
                    break;
                case 18:
                    Layout layout17 = constraint.layout;
                    layout17.guideEnd = typedArray.getDimensionPixelOffset(index, layout17.guideEnd);
                    break;
                case 19:
                    Layout layout18 = constraint.layout;
                    layout18.guidePercent = typedArray.getFloat(index, layout18.guidePercent);
                    break;
                case 20:
                    Layout layout19 = constraint.layout;
                    layout19.horizontalBias = typedArray.getFloat(index, layout19.horizontalBias);
                    break;
                case 21:
                    Layout layout20 = constraint.layout;
                    layout20.mHeight = typedArray.getLayoutDimension(index, layout20.mHeight);
                    break;
                case 22:
                    PropertySet propertySet = constraint.propertySet;
                    propertySet.visibility = typedArray.getInt(index, propertySet.visibility);
                    PropertySet propertySet2 = constraint.propertySet;
                    propertySet2.visibility = VISIBILITY_FLAGS[propertySet2.visibility];
                    break;
                case 23:
                    Layout layout21 = constraint.layout;
                    layout21.mWidth = typedArray.getLayoutDimension(index, layout21.mWidth);
                    break;
                case 24:
                    Layout layout22 = constraint.layout;
                    layout22.leftMargin = typedArray.getDimensionPixelSize(index, layout22.leftMargin);
                    break;
                case 25:
                    Layout layout23 = constraint.layout;
                    layout23.leftToLeft = lookupID(typedArray, index, layout23.leftToLeft);
                    break;
                case 26:
                    Layout layout24 = constraint.layout;
                    layout24.leftToRight = lookupID(typedArray, index, layout24.leftToRight);
                    break;
                case 27:
                    Layout layout25 = constraint.layout;
                    layout25.orientation = typedArray.getInt(index, layout25.orientation);
                    break;
                case 28:
                    Layout layout26 = constraint.layout;
                    layout26.rightMargin = typedArray.getDimensionPixelSize(index, layout26.rightMargin);
                    break;
                case 29:
                    Layout layout27 = constraint.layout;
                    layout27.rightToLeft = lookupID(typedArray, index, layout27.rightToLeft);
                    break;
                case 30:
                    Layout layout28 = constraint.layout;
                    layout28.rightToRight = lookupID(typedArray, index, layout28.rightToRight);
                    break;
                case 31:
                    Layout layout29 = constraint.layout;
                    layout29.startMargin = typedArray.getDimensionPixelSize(index, layout29.startMargin);
                    break;
                case 32:
                    Layout layout30 = constraint.layout;
                    layout30.startToEnd = lookupID(typedArray, index, layout30.startToEnd);
                    break;
                case 33:
                    Layout layout31 = constraint.layout;
                    layout31.startToStart = lookupID(typedArray, index, layout31.startToStart);
                    break;
                case 34:
                    Layout layout32 = constraint.layout;
                    layout32.topMargin = typedArray.getDimensionPixelSize(index, layout32.topMargin);
                    break;
                case 35:
                    Layout layout33 = constraint.layout;
                    layout33.topToBottom = lookupID(typedArray, index, layout33.topToBottom);
                    break;
                case 36:
                    Layout layout34 = constraint.layout;
                    layout34.topToTop = lookupID(typedArray, index, layout34.topToTop);
                    break;
                case 37:
                    Layout layout35 = constraint.layout;
                    layout35.verticalBias = typedArray.getFloat(index, layout35.verticalBias);
                    break;
                case 38:
                    constraint.mViewId = typedArray.getResourceId(index, constraint.mViewId);
                    break;
                case 39:
                    Layout layout36 = constraint.layout;
                    layout36.horizontalWeight = typedArray.getFloat(index, layout36.horizontalWeight);
                    break;
                case 40:
                    Layout layout37 = constraint.layout;
                    layout37.verticalWeight = typedArray.getFloat(index, layout37.verticalWeight);
                    break;
                case 41:
                    Layout layout38 = constraint.layout;
                    layout38.horizontalChainStyle = typedArray.getInt(index, layout38.horizontalChainStyle);
                    break;
                case 42:
                    Layout layout39 = constraint.layout;
                    layout39.verticalChainStyle = typedArray.getInt(index, layout39.verticalChainStyle);
                    break;
                case 43:
                    PropertySet propertySet3 = constraint.propertySet;
                    propertySet3.alpha = typedArray.getFloat(index, propertySet3.alpha);
                    break;
                case 44:
                    Transform transform = constraint.transform;
                    transform.applyElevation = true;
                    transform.elevation = typedArray.getDimension(index, transform.elevation);
                    break;
                case 45:
                    Transform transform2 = constraint.transform;
                    transform2.rotationX = typedArray.getFloat(index, transform2.rotationX);
                    break;
                case 46:
                    Transform transform3 = constraint.transform;
                    transform3.rotationY = typedArray.getFloat(index, transform3.rotationY);
                    break;
                case 47:
                    Transform transform4 = constraint.transform;
                    transform4.scaleX = typedArray.getFloat(index, transform4.scaleX);
                    break;
                case 48:
                    Transform transform5 = constraint.transform;
                    transform5.scaleY = typedArray.getFloat(index, transform5.scaleY);
                    break;
                case 49:
                    Transform transform6 = constraint.transform;
                    transform6.transformPivotX = typedArray.getDimension(index, transform6.transformPivotX);
                    break;
                case 50:
                    Transform transform7 = constraint.transform;
                    transform7.transformPivotY = typedArray.getDimension(index, transform7.transformPivotY);
                    break;
                case 51:
                    Transform transform8 = constraint.transform;
                    transform8.translationX = typedArray.getDimension(index, transform8.translationX);
                    break;
                case 52:
                    Transform transform9 = constraint.transform;
                    transform9.translationY = typedArray.getDimension(index, transform9.translationY);
                    break;
                case 53:
                    Transform transform10 = constraint.transform;
                    transform10.translationZ = typedArray.getDimension(index, transform10.translationZ);
                    break;
                case 54:
                    Layout layout40 = constraint.layout;
                    layout40.widthDefault = typedArray.getInt(index, layout40.widthDefault);
                    break;
                case 55:
                    Layout layout41 = constraint.layout;
                    layout41.heightDefault = typedArray.getInt(index, layout41.heightDefault);
                    break;
                case 56:
                    Layout layout42 = constraint.layout;
                    layout42.widthMax = typedArray.getDimensionPixelSize(index, layout42.widthMax);
                    break;
                case 57:
                    Layout layout43 = constraint.layout;
                    layout43.heightMax = typedArray.getDimensionPixelSize(index, layout43.heightMax);
                    break;
                case 58:
                    Layout layout44 = constraint.layout;
                    layout44.widthMin = typedArray.getDimensionPixelSize(index, layout44.widthMin);
                    break;
                case 59:
                    Layout layout45 = constraint.layout;
                    layout45.heightMin = typedArray.getDimensionPixelSize(index, layout45.heightMin);
                    break;
                case 60:
                    Transform transform11 = constraint.transform;
                    transform11.rotation = typedArray.getFloat(index, transform11.rotation);
                    break;
                case 61:
                    Layout layout46 = constraint.layout;
                    layout46.circleConstraint = lookupID(typedArray, index, layout46.circleConstraint);
                    break;
                case 62:
                    Layout layout47 = constraint.layout;
                    layout47.circleRadius = typedArray.getDimensionPixelSize(index, layout47.circleRadius);
                    break;
                case 63:
                    Layout layout48 = constraint.layout;
                    layout48.circleAngle = typedArray.getFloat(index, layout48.circleAngle);
                    break;
                case 64:
                    Motion motion = constraint.motion;
                    motion.mAnimateRelativeTo = lookupID(typedArray, index, motion.mAnimateRelativeTo);
                    break;
                case 65:
                    if (typedArray.peekValue(index).type == 3) {
                        constraint.motion.mTransitionEasing = typedArray.getString(index);
                        break;
                    } else {
                        constraint.motion.mTransitionEasing = Easing.NAMED_EASING[typedArray.getInteger(index, 0)];
                        break;
                    }
                case 66:
                    constraint.motion.mDrawPath = typedArray.getInt(index, 0);
                    break;
                case 67:
                    Motion motion2 = constraint.motion;
                    motion2.mPathRotate = typedArray.getFloat(index, motion2.mPathRotate);
                    break;
                case 68:
                    PropertySet propertySet4 = constraint.propertySet;
                    propertySet4.mProgress = typedArray.getFloat(index, propertySet4.mProgress);
                    break;
                case 69:
                    constraint.layout.widthPercent = typedArray.getFloat(index, 1.0f);
                    break;
                case 70:
                    constraint.layout.heightPercent = typedArray.getFloat(index, 1.0f);
                    break;
                case 71:
                    break;
                case 72:
                    Layout layout49 = constraint.layout;
                    layout49.mBarrierDirection = typedArray.getInt(index, layout49.mBarrierDirection);
                    break;
                case 73:
                    Layout layout50 = constraint.layout;
                    layout50.mBarrierMargin = typedArray.getDimensionPixelSize(index, layout50.mBarrierMargin);
                    break;
                case 74:
                    constraint.layout.mReferenceIdString = typedArray.getString(index);
                    break;
                case 75:
                    Layout layout51 = constraint.layout;
                    layout51.mBarrierAllowsGoneWidgets = typedArray.getBoolean(index, layout51.mBarrierAllowsGoneWidgets);
                    break;
                case 76:
                    Motion motion3 = constraint.motion;
                    motion3.mPathMotionArc = typedArray.getInt(index, motion3.mPathMotionArc);
                    break;
                case 77:
                    constraint.layout.mConstraintTag = typedArray.getString(index);
                    break;
                case 78:
                    PropertySet propertySet5 = constraint.propertySet;
                    propertySet5.mVisibilityMode = typedArray.getInt(index, propertySet5.mVisibilityMode);
                    break;
                case 79:
                    Motion motion4 = constraint.motion;
                    motion4.mMotionStagger = typedArray.getFloat(index, motion4.mMotionStagger);
                    break;
                case 80:
                    Layout layout52 = constraint.layout;
                    layout52.constrainedWidth = typedArray.getBoolean(index, layout52.constrainedWidth);
                    break;
                case 81:
                    Layout layout53 = constraint.layout;
                    layout53.constrainedHeight = typedArray.getBoolean(index, layout53.constrainedHeight);
                    break;
                case 82:
                    Integer.toHexString(index);
                    mapToConstant.get(index);
                    break;
                default:
                    Integer.toHexString(index);
                    mapToConstant.get(index);
                    break;
            }
        }
    }

    private String sideToString(int i2) {
        switch (i2) {
            case 1:
                return "left";
            case 2:
                return "right";
            case 3:
                return "top";
            case 4:
                return "bottom";
            case 5:
                return "baseline";
            case 6:
                return "start";
            case 7:
                return "end";
            default:
                return "undefined";
        }
    }

    private static String[] splitString(String str) {
        char[] charArray = str.toCharArray();
        ArrayList arrayList = new ArrayList();
        int i2 = 0;
        boolean z = false;
        for (int i3 = 0; i3 < charArray.length; i3++) {
            if (charArray[i3] == ',' && !z) {
                arrayList.add(new String(charArray, i2, i3 - i2));
                i2 = i3 + 1;
            } else if (charArray[i3] == '\"') {
                z = !z;
            }
        }
        arrayList.add(new String(charArray, i2, charArray.length - i2));
        return (String[]) arrayList.toArray(new String[arrayList.size()]);
    }

    public void addColorAttributes(String... strArr) {
        addAttributes(ConstraintAttribute.AttributeType.COLOR_TYPE, strArr);
    }

    public void addFloatAttributes(String... strArr) {
        addAttributes(ConstraintAttribute.AttributeType.FLOAT_TYPE, strArr);
    }

    public void addIntAttributes(String... strArr) {
        addAttributes(ConstraintAttribute.AttributeType.INT_TYPE, strArr);
    }

    public void addStringAttributes(String... strArr) {
        addAttributes(ConstraintAttribute.AttributeType.STRING_TYPE, strArr);
    }

    public void addToHorizontalChain(int i2, int i3, int i4) {
        connect(i2, 1, i3, i3 == 0 ? 1 : 2, 0);
        connect(i2, 2, i4, i4 == 0 ? 2 : 1, 0);
        if (i3 != 0) {
            connect(i3, 2, i2, 1, 0);
        }
        if (i4 != 0) {
            connect(i4, 1, i2, 2, 0);
        }
    }

    public void addToHorizontalChainRTL(int i2, int i3, int i4) {
        connect(i2, 6, i3, i3 == 0 ? 6 : 7, 0);
        connect(i2, 7, i4, i4 == 0 ? 7 : 6, 0);
        if (i3 != 0) {
            connect(i3, 7, i2, 6, 0);
        }
        if (i4 != 0) {
            connect(i4, 6, i2, 7, 0);
        }
    }

    public void addToVerticalChain(int i2, int i3, int i4) {
        connect(i2, 3, i3, i3 == 0 ? 3 : 4, 0);
        connect(i2, 4, i4, i4 == 0 ? 4 : 3, 0);
        if (i3 != 0) {
            connect(i3, 4, i2, 3, 0);
        }
        if (i4 != 0) {
            connect(i4, 3, i2, 4, 0);
        }
    }

    public void applyCustomAttributes(ConstraintLayout constraintLayout) {
        int childCount = constraintLayout.getChildCount();
        for (int i2 = 0; i2 < childCount; i2++) {
            View childAt = constraintLayout.getChildAt(i2);
            int id = childAt.getId();
            if (!this.mConstraints.containsKey(Integer.valueOf(id))) {
                Debug.getName(childAt);
            } else {
                if (this.mForceId && id == -1) {
                    throw new RuntimeException("All children of ConstraintLayout must have ids to use ConstraintSet");
                }
                if (this.mConstraints.containsKey(Integer.valueOf(id))) {
                    ConstraintAttribute.setAttributes(childAt, this.mConstraints.get(Integer.valueOf(id)).mCustomConstraints);
                }
            }
        }
    }

    public void applyTo(ConstraintLayout constraintLayout) {
        applyToInternal(constraintLayout, true);
        constraintLayout.setConstraintSet(null);
        constraintLayout.requestLayout();
    }

    public void applyToHelper(ConstraintHelper constraintHelper, ConstraintWidget constraintWidget, ConstraintLayout.LayoutParams layoutParams, SparseArray<ConstraintWidget> sparseArray) {
        int id = constraintHelper.getId();
        if (this.mConstraints.containsKey(Integer.valueOf(id))) {
            Constraint constraint = this.mConstraints.get(Integer.valueOf(id));
            if (constraintWidget instanceof HelperWidget) {
                constraintHelper.loadParameters(constraint, (HelperWidget) constraintWidget, layoutParams, sparseArray);
            }
        }
    }

    public void applyToInternal(ConstraintLayout constraintLayout, boolean z) {
        int childCount = constraintLayout.getChildCount();
        HashSet hashSet = new HashSet(this.mConstraints.keySet());
        for (int i2 = 0; i2 < childCount; i2++) {
            View childAt = constraintLayout.getChildAt(i2);
            int id = childAt.getId();
            if (!this.mConstraints.containsKey(Integer.valueOf(id))) {
                Debug.getName(childAt);
            } else {
                if (this.mForceId && id == -1) {
                    throw new RuntimeException("All children of ConstraintLayout must have ids to use ConstraintSet");
                }
                if (id != -1 && this.mConstraints.containsKey(Integer.valueOf(id))) {
                    hashSet.remove(Integer.valueOf(id));
                    Constraint constraint = this.mConstraints.get(Integer.valueOf(id));
                    if (childAt instanceof Barrier) {
                        constraint.layout.mHelperType = 1;
                    }
                    int i3 = constraint.layout.mHelperType;
                    if (i3 != -1 && i3 == 1) {
                        Barrier barrier = (Barrier) childAt;
                        barrier.setId(id);
                        barrier.setType(constraint.layout.mBarrierDirection);
                        barrier.setMargin(constraint.layout.mBarrierMargin);
                        barrier.setAllowsGoneWidget(constraint.layout.mBarrierAllowsGoneWidgets);
                        Layout layout = constraint.layout;
                        int[] iArr = layout.mReferenceIds;
                        if (iArr != null) {
                            barrier.setReferencedIds(iArr);
                        } else {
                            String str = layout.mReferenceIdString;
                            if (str != null) {
                                layout.mReferenceIds = convertReferenceString(barrier, str);
                                barrier.setReferencedIds(constraint.layout.mReferenceIds);
                            }
                        }
                    }
                    ConstraintLayout.LayoutParams layoutParams = (ConstraintLayout.LayoutParams) childAt.getLayoutParams();
                    layoutParams.validate();
                    constraint.applyTo(layoutParams);
                    if (z) {
                        ConstraintAttribute.setAttributes(childAt, constraint.mCustomConstraints);
                    }
                    childAt.setLayoutParams(layoutParams);
                    PropertySet propertySet = constraint.propertySet;
                    if (propertySet.mVisibilityMode == 0) {
                        childAt.setVisibility(propertySet.visibility);
                    }
                    childAt.setAlpha(constraint.propertySet.alpha);
                    childAt.setRotation(constraint.transform.rotation);
                    childAt.setRotationX(constraint.transform.rotationX);
                    childAt.setRotationY(constraint.transform.rotationY);
                    childAt.setScaleX(constraint.transform.scaleX);
                    childAt.setScaleY(constraint.transform.scaleY);
                    if (!Float.isNaN(constraint.transform.transformPivotX)) {
                        childAt.setPivotX(constraint.transform.transformPivotX);
                    }
                    if (!Float.isNaN(constraint.transform.transformPivotY)) {
                        childAt.setPivotY(constraint.transform.transformPivotY);
                    }
                    childAt.setTranslationX(constraint.transform.translationX);
                    childAt.setTranslationY(constraint.transform.translationY);
                    childAt.setTranslationZ(constraint.transform.translationZ);
                    Transform transform = constraint.transform;
                    if (transform.applyElevation) {
                        childAt.setElevation(transform.elevation);
                    }
                }
            }
        }
        Iterator it = hashSet.iterator();
        while (it.hasNext()) {
            Integer num = (Integer) it.next();
            Constraint constraint2 = this.mConstraints.get(num);
            int i4 = constraint2.layout.mHelperType;
            if (i4 != -1 && i4 == 1) {
                Barrier barrier2 = new Barrier(constraintLayout.getContext());
                barrier2.setId(num.intValue());
                Layout layout2 = constraint2.layout;
                int[] iArr2 = layout2.mReferenceIds;
                if (iArr2 != null) {
                    barrier2.setReferencedIds(iArr2);
                } else {
                    String str2 = layout2.mReferenceIdString;
                    if (str2 != null) {
                        layout2.mReferenceIds = convertReferenceString(barrier2, str2);
                        barrier2.setReferencedIds(constraint2.layout.mReferenceIds);
                    }
                }
                barrier2.setType(constraint2.layout.mBarrierDirection);
                barrier2.setMargin(constraint2.layout.mBarrierMargin);
                ConstraintLayout.LayoutParams generateDefaultLayoutParams = constraintLayout.generateDefaultLayoutParams();
                barrier2.validateParams();
                constraint2.applyTo(generateDefaultLayoutParams);
                constraintLayout.addView(barrier2, generateDefaultLayoutParams);
            }
            if (constraint2.layout.mIsGuideline) {
                View guideline = new Guideline(constraintLayout.getContext());
                guideline.setId(num.intValue());
                ConstraintLayout.LayoutParams generateDefaultLayoutParams2 = constraintLayout.generateDefaultLayoutParams();
                constraint2.applyTo(generateDefaultLayoutParams2);
                constraintLayout.addView(guideline, generateDefaultLayoutParams2);
            }
        }
    }

    public void applyToLayoutParams(int i2, ConstraintLayout.LayoutParams layoutParams) {
        if (this.mConstraints.containsKey(Integer.valueOf(i2))) {
            this.mConstraints.get(Integer.valueOf(i2)).applyTo(layoutParams);
        }
    }

    public void applyToWithoutCustom(ConstraintLayout constraintLayout) {
        applyToInternal(constraintLayout, false);
        constraintLayout.setConstraintSet(null);
    }

    public void center(int i2, int i3, int i4, int i5, int i6, int i7, int i8, float f2) {
        if (i5 < 0) {
            throw new IllegalArgumentException("margin must be > 0");
        }
        if (i8 < 0) {
            throw new IllegalArgumentException("margin must be > 0");
        }
        if (f2 <= 0.0f || f2 > 1.0f) {
            throw new IllegalArgumentException("bias must be between 0 and 1 inclusive");
        }
        if (i4 == 1 || i4 == 2) {
            connect(i2, 1, i3, i4, i5);
            connect(i2, 2, i6, i7, i8);
            this.mConstraints.get(Integer.valueOf(i2)).layout.horizontalBias = f2;
        } else if (i4 == 6 || i4 == 7) {
            connect(i2, 6, i3, i4, i5);
            connect(i2, 7, i6, i7, i8);
            this.mConstraints.get(Integer.valueOf(i2)).layout.horizontalBias = f2;
        } else {
            connect(i2, 3, i3, i4, i5);
            connect(i2, 4, i6, i7, i8);
            this.mConstraints.get(Integer.valueOf(i2)).layout.verticalBias = f2;
        }
    }

    public void centerHorizontally(int i2, int i3, int i4, int i5, int i6, int i7, int i8, float f2) {
        connect(i2, 1, i3, i4, i5);
        connect(i2, 2, i6, i7, i8);
        this.mConstraints.get(Integer.valueOf(i2)).layout.horizontalBias = f2;
    }

    public void centerHorizontallyRtl(int i2, int i3, int i4, int i5, int i6, int i7, int i8, float f2) {
        connect(i2, 6, i3, i4, i5);
        connect(i2, 7, i6, i7, i8);
        this.mConstraints.get(Integer.valueOf(i2)).layout.horizontalBias = f2;
    }

    public void centerVertically(int i2, int i3, int i4, int i5, int i6, int i7, int i8, float f2) {
        connect(i2, 3, i3, i4, i5);
        connect(i2, 4, i6, i7, i8);
        this.mConstraints.get(Integer.valueOf(i2)).layout.verticalBias = f2;
    }

    public void clear(int i2) {
        this.mConstraints.remove(Integer.valueOf(i2));
    }

    public void clone(Context context, int i2) {
        clone((ConstraintLayout) LayoutInflater.from(context).inflate(i2, (ViewGroup) null));
    }

    public void connect(int i2, int i3, int i4, int i5, int i6) {
        if (!this.mConstraints.containsKey(Integer.valueOf(i2))) {
            this.mConstraints.put(Integer.valueOf(i2), new Constraint());
        }
        Constraint constraint = this.mConstraints.get(Integer.valueOf(i2));
        switch (i3) {
            case 1:
                if (i5 == 1) {
                    Layout layout = constraint.layout;
                    layout.leftToLeft = i4;
                    layout.leftToRight = -1;
                } else {
                    if (i5 != 2) {
                        throw new IllegalArgumentException(C1499a.m582D(C1499a.m586H("Left to "), sideToString(i5), " undefined"));
                    }
                    Layout layout2 = constraint.layout;
                    layout2.leftToRight = i4;
                    layout2.leftToLeft = -1;
                }
                constraint.layout.leftMargin = i6;
                return;
            case 2:
                if (i5 == 1) {
                    Layout layout3 = constraint.layout;
                    layout3.rightToLeft = i4;
                    layout3.rightToRight = -1;
                } else {
                    if (i5 != 2) {
                        throw new IllegalArgumentException(C1499a.m582D(C1499a.m586H("right to "), sideToString(i5), " undefined"));
                    }
                    Layout layout4 = constraint.layout;
                    layout4.rightToRight = i4;
                    layout4.rightToLeft = -1;
                }
                constraint.layout.rightMargin = i6;
                return;
            case 3:
                if (i5 == 3) {
                    Layout layout5 = constraint.layout;
                    layout5.topToTop = i4;
                    layout5.topToBottom = -1;
                    layout5.baselineToBaseline = -1;
                } else {
                    if (i5 != 4) {
                        throw new IllegalArgumentException(C1499a.m582D(C1499a.m586H("right to "), sideToString(i5), " undefined"));
                    }
                    Layout layout6 = constraint.layout;
                    layout6.topToBottom = i4;
                    layout6.topToTop = -1;
                    layout6.baselineToBaseline = -1;
                }
                constraint.layout.topMargin = i6;
                return;
            case 4:
                if (i5 == 4) {
                    Layout layout7 = constraint.layout;
                    layout7.bottomToBottom = i4;
                    layout7.bottomToTop = -1;
                    layout7.baselineToBaseline = -1;
                } else {
                    if (i5 != 3) {
                        throw new IllegalArgumentException(C1499a.m582D(C1499a.m586H("right to "), sideToString(i5), " undefined"));
                    }
                    Layout layout8 = constraint.layout;
                    layout8.bottomToTop = i4;
                    layout8.bottomToBottom = -1;
                    layout8.baselineToBaseline = -1;
                }
                constraint.layout.bottomMargin = i6;
                return;
            case 5:
                if (i5 != 5) {
                    throw new IllegalArgumentException(C1499a.m582D(C1499a.m586H("right to "), sideToString(i5), " undefined"));
                }
                Layout layout9 = constraint.layout;
                layout9.baselineToBaseline = i4;
                layout9.bottomToBottom = -1;
                layout9.bottomToTop = -1;
                layout9.topToTop = -1;
                layout9.topToBottom = -1;
                return;
            case 6:
                if (i5 == 6) {
                    Layout layout10 = constraint.layout;
                    layout10.startToStart = i4;
                    layout10.startToEnd = -1;
                } else {
                    if (i5 != 7) {
                        throw new IllegalArgumentException(C1499a.m582D(C1499a.m586H("right to "), sideToString(i5), " undefined"));
                    }
                    Layout layout11 = constraint.layout;
                    layout11.startToEnd = i4;
                    layout11.startToStart = -1;
                }
                constraint.layout.startMargin = i6;
                return;
            case 7:
                if (i5 == 7) {
                    Layout layout12 = constraint.layout;
                    layout12.endToEnd = i4;
                    layout12.endToStart = -1;
                } else {
                    if (i5 != 6) {
                        throw new IllegalArgumentException(C1499a.m582D(C1499a.m586H("right to "), sideToString(i5), " undefined"));
                    }
                    Layout layout13 = constraint.layout;
                    layout13.endToStart = i4;
                    layout13.endToEnd = -1;
                }
                constraint.layout.endMargin = i6;
                return;
            default:
                StringBuilder sb = new StringBuilder();
                sb.append(sideToString(i3));
                sb.append(" to ");
                throw new IllegalArgumentException(C1499a.m582D(sb, sideToString(i5), " unknown"));
        }
    }

    public void constrainCircle(int i2, int i3, int i4, float f2) {
        Layout layout = get(i2).layout;
        layout.circleConstraint = i3;
        layout.circleRadius = i4;
        layout.circleAngle = f2;
    }

    public void constrainDefaultHeight(int i2, int i3) {
        get(i2).layout.heightDefault = i3;
    }

    public void constrainDefaultWidth(int i2, int i3) {
        get(i2).layout.widthDefault = i3;
    }

    public void constrainHeight(int i2, int i3) {
        get(i2).layout.mHeight = i3;
    }

    public void constrainMaxHeight(int i2, int i3) {
        get(i2).layout.heightMax = i3;
    }

    public void constrainMaxWidth(int i2, int i3) {
        get(i2).layout.widthMax = i3;
    }

    public void constrainMinHeight(int i2, int i3) {
        get(i2).layout.heightMin = i3;
    }

    public void constrainMinWidth(int i2, int i3) {
        get(i2).layout.widthMin = i3;
    }

    public void constrainPercentHeight(int i2, float f2) {
        get(i2).layout.heightPercent = f2;
    }

    public void constrainPercentWidth(int i2, float f2) {
        get(i2).layout.widthPercent = f2;
    }

    public void constrainWidth(int i2, int i3) {
        get(i2).layout.mWidth = i3;
    }

    public void constrainedHeight(int i2, boolean z) {
        get(i2).layout.constrainedHeight = z;
    }

    public void constrainedWidth(int i2, boolean z) {
        get(i2).layout.constrainedWidth = z;
    }

    public void create(int i2, int i3) {
        Layout layout = get(i2).layout;
        layout.mIsGuideline = true;
        layout.orientation = i3;
    }

    public void createBarrier(int i2, int i3, int i4, int... iArr) {
        Layout layout = get(i2).layout;
        layout.mHelperType = 1;
        layout.mBarrierDirection = i3;
        layout.mBarrierMargin = i4;
        layout.mIsGuideline = false;
        layout.mReferenceIds = iArr;
    }

    public void createHorizontalChain(int i2, int i3, int i4, int i5, int[] iArr, float[] fArr, int i6) {
        createHorizontalChain(i2, i3, i4, i5, iArr, fArr, i6, 1, 2);
    }

    public void createHorizontalChainRtl(int i2, int i3, int i4, int i5, int[] iArr, float[] fArr, int i6) {
        createHorizontalChain(i2, i3, i4, i5, iArr, fArr, i6, 6, 7);
    }

    public void createVerticalChain(int i2, int i3, int i4, int i5, int[] iArr, float[] fArr, int i6) {
        if (iArr.length < 2) {
            throw new IllegalArgumentException("must have 2 or more widgets in a chain");
        }
        if (fArr != null && fArr.length != iArr.length) {
            throw new IllegalArgumentException("must have 2 or more widgets in a chain");
        }
        if (fArr != null) {
            get(iArr[0]).layout.verticalWeight = fArr[0];
        }
        get(iArr[0]).layout.verticalChainStyle = i6;
        connect(iArr[0], 3, i2, i3, 0);
        for (int i7 = 1; i7 < iArr.length; i7++) {
            int i8 = iArr[i7];
            int i9 = i7 - 1;
            connect(iArr[i7], 3, iArr[i9], 4, 0);
            connect(iArr[i9], 4, iArr[i7], 3, 0);
            if (fArr != null) {
                get(iArr[i7]).layout.verticalWeight = fArr[i7];
            }
        }
        connect(iArr[iArr.length - 1], 4, i4, i5, 0);
    }

    public void dump(MotionScene motionScene, int... iArr) {
        HashSet hashSet;
        Set<Integer> keySet = this.mConstraints.keySet();
        if (iArr.length != 0) {
            hashSet = new HashSet();
            for (int i2 : iArr) {
                hashSet.add(Integer.valueOf(i2));
            }
        } else {
            hashSet = new HashSet(keySet);
        }
        System.out.println(hashSet.size() + " constraints");
        StringBuilder sb = new StringBuilder();
        for (Integer num : (Integer[]) hashSet.toArray(new Integer[0])) {
            Constraint constraint = this.mConstraints.get(num);
            sb.append("<Constraint id=");
            sb.append(num);
            sb.append(" \n");
            constraint.layout.dump(motionScene, sb);
            sb.append("/>\n");
        }
        System.out.println(sb.toString());
    }

    public boolean getApplyElevation(int i2) {
        return get(i2).transform.applyElevation;
    }

    public Constraint getConstraint(int i2) {
        if (this.mConstraints.containsKey(Integer.valueOf(i2))) {
            return this.mConstraints.get(Integer.valueOf(i2));
        }
        return null;
    }

    public HashMap<String, ConstraintAttribute> getCustomAttributeSet() {
        return this.mSavedAttributes;
    }

    public int getHeight(int i2) {
        return get(i2).layout.mHeight;
    }

    public int[] getKnownIds() {
        Integer[] numArr = (Integer[]) this.mConstraints.keySet().toArray(new Integer[0]);
        int length = numArr.length;
        int[] iArr = new int[length];
        for (int i2 = 0; i2 < length; i2++) {
            iArr[i2] = numArr[i2].intValue();
        }
        return iArr;
    }

    public Constraint getParameters(int i2) {
        return get(i2);
    }

    public int[] getReferencedIds(int i2) {
        int[] iArr = get(i2).layout.mReferenceIds;
        return iArr == null ? new int[0] : Arrays.copyOf(iArr, iArr.length);
    }

    public int getVisibility(int i2) {
        return get(i2).propertySet.visibility;
    }

    public int getVisibilityMode(int i2) {
        return get(i2).propertySet.mVisibilityMode;
    }

    public int getWidth(int i2) {
        return get(i2).layout.mWidth;
    }

    public boolean isForceId() {
        return this.mForceId;
    }

    public void load(Context context, int i2) {
        XmlResourceParser xml = context.getResources().getXml(i2);
        try {
            for (int eventType = xml.getEventType(); eventType != 1; eventType = xml.next()) {
                if (eventType == 0) {
                    xml.getName();
                } else if (eventType == 2) {
                    String name = xml.getName();
                    Constraint fillFromAttributeList = fillFromAttributeList(context, Xml.asAttributeSet(xml));
                    if (name.equalsIgnoreCase("Guideline")) {
                        fillFromAttributeList.layout.mIsGuideline = true;
                    }
                    this.mConstraints.put(Integer.valueOf(fillFromAttributeList.mViewId), fillFromAttributeList);
                }
            }
        } catch (IOException e2) {
            e2.printStackTrace();
        } catch (XmlPullParserException e3) {
            e3.printStackTrace();
        }
    }

    public void parseColorAttributes(Constraint constraint, String str) {
        String[] split = str.split(ChineseToPinyinResource.Field.COMMA);
        for (int i2 = 0; i2 < split.length; i2++) {
            String[] split2 = split[i2].split("=");
            if (split2.length != 2) {
                String str2 = split[i2];
            } else {
                constraint.setColorValue(split2[0], Color.parseColor(split2[1]));
            }
        }
    }

    public void parseFloatAttributes(Constraint constraint, String str) {
        String[] split = str.split(ChineseToPinyinResource.Field.COMMA);
        for (int i2 = 0; i2 < split.length; i2++) {
            String[] split2 = split[i2].split("=");
            if (split2.length != 2) {
                String str2 = split[i2];
            } else {
                constraint.setFloatValue(split2[0], Float.parseFloat(split2[1]));
            }
        }
    }

    public void parseIntAttributes(Constraint constraint, String str) {
        String[] split = str.split(ChineseToPinyinResource.Field.COMMA);
        for (int i2 = 0; i2 < split.length; i2++) {
            String[] split2 = split[i2].split("=");
            if (split2.length != 2) {
                String str2 = split[i2];
            } else {
                constraint.setFloatValue(split2[0], Integer.decode(split2[1]).intValue());
            }
        }
    }

    public void parseStringAttributes(Constraint constraint, String str) {
        String[] splitString = splitString(str);
        for (int i2 = 0; i2 < splitString.length; i2++) {
            String[] split = splitString[i2].split("=");
            String str2 = splitString[i2];
            constraint.setStringValue(split[0], split[1]);
        }
    }

    public void readFallback(ConstraintSet constraintSet) {
        for (Integer num : constraintSet.mConstraints.keySet()) {
            int intValue = num.intValue();
            Constraint constraint = constraintSet.mConstraints.get(num);
            if (!this.mConstraints.containsKey(Integer.valueOf(intValue))) {
                this.mConstraints.put(Integer.valueOf(intValue), new Constraint());
            }
            Constraint constraint2 = this.mConstraints.get(Integer.valueOf(intValue));
            Layout layout = constraint2.layout;
            if (!layout.mApply) {
                layout.copyFrom(constraint.layout);
            }
            PropertySet propertySet = constraint2.propertySet;
            if (!propertySet.mApply) {
                propertySet.copyFrom(constraint.propertySet);
            }
            Transform transform = constraint2.transform;
            if (!transform.mApply) {
                transform.copyFrom(constraint.transform);
            }
            Motion motion = constraint2.motion;
            if (!motion.mApply) {
                motion.copyFrom(constraint.motion);
            }
            for (String str : constraint.mCustomConstraints.keySet()) {
                if (!constraint2.mCustomConstraints.containsKey(str)) {
                    constraint2.mCustomConstraints.put(str, constraint.mCustomConstraints.get(str));
                }
            }
        }
    }

    public void removeAttribute(String str) {
        this.mSavedAttributes.remove(str);
    }

    public void removeFromHorizontalChain(int i2) {
        if (this.mConstraints.containsKey(Integer.valueOf(i2))) {
            Layout layout = this.mConstraints.get(Integer.valueOf(i2)).layout;
            int i3 = layout.leftToRight;
            int i4 = layout.rightToLeft;
            if (i3 != -1 || i4 != -1) {
                if (i3 != -1 && i4 != -1) {
                    connect(i3, 2, i4, 1, 0);
                    connect(i4, 1, i3, 2, 0);
                } else if (i3 != -1 || i4 != -1) {
                    int i5 = layout.rightToRight;
                    if (i5 != -1) {
                        connect(i3, 2, i5, 2, 0);
                    } else {
                        int i6 = layout.leftToLeft;
                        if (i6 != -1) {
                            connect(i4, 1, i6, 1, 0);
                        }
                    }
                }
                clear(i2, 1);
                clear(i2, 2);
                return;
            }
            int i7 = layout.startToEnd;
            int i8 = layout.endToStart;
            if (i7 != -1 || i8 != -1) {
                if (i7 != -1 && i8 != -1) {
                    connect(i7, 7, i8, 6, 0);
                    connect(i8, 6, i3, 7, 0);
                } else if (i3 != -1 || i8 != -1) {
                    int i9 = layout.rightToRight;
                    if (i9 != -1) {
                        connect(i3, 7, i9, 7, 0);
                    } else {
                        int i10 = layout.leftToLeft;
                        if (i10 != -1) {
                            connect(i8, 6, i10, 6, 0);
                        }
                    }
                }
            }
            clear(i2, 6);
            clear(i2, 7);
        }
    }

    public void removeFromVerticalChain(int i2) {
        if (this.mConstraints.containsKey(Integer.valueOf(i2))) {
            Layout layout = this.mConstraints.get(Integer.valueOf(i2)).layout;
            int i3 = layout.topToBottom;
            int i4 = layout.bottomToTop;
            if (i3 != -1 || i4 != -1) {
                if (i3 != -1 && i4 != -1) {
                    connect(i3, 4, i4, 3, 0);
                    connect(i4, 3, i3, 4, 0);
                } else if (i3 != -1 || i4 != -1) {
                    int i5 = layout.bottomToBottom;
                    if (i5 != -1) {
                        connect(i3, 4, i5, 4, 0);
                    } else {
                        int i6 = layout.topToTop;
                        if (i6 != -1) {
                            connect(i4, 3, i6, 3, 0);
                        }
                    }
                }
            }
        }
        clear(i2, 3);
        clear(i2, 4);
    }

    public void setAlpha(int i2, float f2) {
        get(i2).propertySet.alpha = f2;
    }

    public void setApplyElevation(int i2, boolean z) {
        get(i2).transform.applyElevation = z;
    }

    public void setBarrierType(int i2, int i3) {
        get(i2).layout.mHelperType = i3;
    }

    public void setColorValue(int i2, String str, int i3) {
        get(i2).setColorValue(str, i3);
    }

    public void setDimensionRatio(int i2, String str) {
        get(i2).layout.dimensionRatio = str;
    }

    public void setEditorAbsoluteX(int i2, int i3) {
        get(i2).layout.editorAbsoluteX = i3;
    }

    public void setEditorAbsoluteY(int i2, int i3) {
        get(i2).layout.editorAbsoluteY = i3;
    }

    public void setElevation(int i2, float f2) {
        get(i2).transform.elevation = f2;
        get(i2).transform.applyElevation = true;
    }

    public void setFloatValue(int i2, String str, float f2) {
        get(i2).setFloatValue(str, f2);
    }

    public void setForceId(boolean z) {
        this.mForceId = z;
    }

    public void setGoneMargin(int i2, int i3, int i4) {
        Constraint constraint = get(i2);
        switch (i3) {
            case 1:
                constraint.layout.goneLeftMargin = i4;
                return;
            case 2:
                constraint.layout.goneRightMargin = i4;
                return;
            case 3:
                constraint.layout.goneTopMargin = i4;
                return;
            case 4:
                constraint.layout.goneBottomMargin = i4;
                return;
            case 5:
                throw new IllegalArgumentException("baseline does not support margins");
            case 6:
                constraint.layout.goneStartMargin = i4;
                return;
            case 7:
                constraint.layout.goneEndMargin = i4;
                return;
            default:
                throw new IllegalArgumentException("unknown constraint");
        }
    }

    public void setGuidelineBegin(int i2, int i3) {
        get(i2).layout.guideBegin = i3;
        get(i2).layout.guideEnd = -1;
        get(i2).layout.guidePercent = -1.0f;
    }

    public void setGuidelineEnd(int i2, int i3) {
        get(i2).layout.guideEnd = i3;
        get(i2).layout.guideBegin = -1;
        get(i2).layout.guidePercent = -1.0f;
    }

    public void setGuidelinePercent(int i2, float f2) {
        get(i2).layout.guidePercent = f2;
        get(i2).layout.guideEnd = -1;
        get(i2).layout.guideBegin = -1;
    }

    public void setHorizontalBias(int i2, float f2) {
        get(i2).layout.horizontalBias = f2;
    }

    public void setHorizontalChainStyle(int i2, int i3) {
        get(i2).layout.horizontalChainStyle = i3;
    }

    public void setHorizontalWeight(int i2, float f2) {
        get(i2).layout.horizontalWeight = f2;
    }

    public void setIntValue(int i2, String str, int i3) {
        get(i2).setIntValue(str, i3);
    }

    public void setMargin(int i2, int i3, int i4) {
        Constraint constraint = get(i2);
        switch (i3) {
            case 1:
                constraint.layout.leftMargin = i4;
                return;
            case 2:
                constraint.layout.rightMargin = i4;
                return;
            case 3:
                constraint.layout.topMargin = i4;
                return;
            case 4:
                constraint.layout.bottomMargin = i4;
                return;
            case 5:
                throw new IllegalArgumentException("baseline does not support margins");
            case 6:
                constraint.layout.startMargin = i4;
                return;
            case 7:
                constraint.layout.endMargin = i4;
                return;
            default:
                throw new IllegalArgumentException("unknown constraint");
        }
    }

    public void setReferencedIds(int i2, int... iArr) {
        get(i2).layout.mReferenceIds = iArr;
    }

    public void setRotation(int i2, float f2) {
        get(i2).transform.rotation = f2;
    }

    public void setRotationX(int i2, float f2) {
        get(i2).transform.rotationX = f2;
    }

    public void setRotationY(int i2, float f2) {
        get(i2).transform.rotationY = f2;
    }

    public void setScaleX(int i2, float f2) {
        get(i2).transform.scaleX = f2;
    }

    public void setScaleY(int i2, float f2) {
        get(i2).transform.scaleY = f2;
    }

    public void setStringValue(int i2, String str, String str2) {
        get(i2).setStringValue(str, str2);
    }

    public void setTransformPivot(int i2, float f2, float f3) {
        Transform transform = get(i2).transform;
        transform.transformPivotY = f3;
        transform.transformPivotX = f2;
    }

    public void setTransformPivotX(int i2, float f2) {
        get(i2).transform.transformPivotX = f2;
    }

    public void setTransformPivotY(int i2, float f2) {
        get(i2).transform.transformPivotY = f2;
    }

    public void setTranslation(int i2, float f2, float f3) {
        Transform transform = get(i2).transform;
        transform.translationX = f2;
        transform.translationY = f3;
    }

    public void setTranslationX(int i2, float f2) {
        get(i2).transform.translationX = f2;
    }

    public void setTranslationY(int i2, float f2) {
        get(i2).transform.translationY = f2;
    }

    public void setTranslationZ(int i2, float f2) {
        get(i2).transform.translationZ = f2;
    }

    public void setValidateOnParse(boolean z) {
        this.mValidate = z;
    }

    public void setVerticalBias(int i2, float f2) {
        get(i2).layout.verticalBias = f2;
    }

    public void setVerticalChainStyle(int i2, int i3) {
        get(i2).layout.verticalChainStyle = i3;
    }

    public void setVerticalWeight(int i2, float f2) {
        get(i2).layout.verticalWeight = f2;
    }

    public void setVisibility(int i2, int i3) {
        get(i2).propertySet.visibility = i3;
    }

    public void setVisibilityMode(int i2, int i3) {
        get(i2).propertySet.mVisibilityMode = i3;
    }

    private void createHorizontalChain(int i2, int i3, int i4, int i5, int[] iArr, float[] fArr, int i6, int i7, int i8) {
        if (iArr.length < 2) {
            throw new IllegalArgumentException("must have 2 or more widgets in a chain");
        }
        if (fArr != null && fArr.length != iArr.length) {
            throw new IllegalArgumentException("must have 2 or more widgets in a chain");
        }
        if (fArr != null) {
            get(iArr[0]).layout.horizontalWeight = fArr[0];
        }
        get(iArr[0]).layout.horizontalChainStyle = i6;
        connect(iArr[0], i7, i2, i3, -1);
        for (int i9 = 1; i9 < iArr.length; i9++) {
            int i10 = iArr[i9];
            int i11 = i9 - 1;
            connect(iArr[i9], i7, iArr[i11], i8, -1);
            connect(iArr[i11], i8, iArr[i9], i7, -1);
            if (fArr != null) {
                get(iArr[i9]).layout.horizontalWeight = fArr[i9];
            }
        }
        connect(iArr[iArr.length - 1], i8, i4, i5, -1);
    }

    public void clear(int i2, int i3) {
        if (this.mConstraints.containsKey(Integer.valueOf(i2))) {
            Constraint constraint = this.mConstraints.get(Integer.valueOf(i2));
            switch (i3) {
                case 1:
                    Layout layout = constraint.layout;
                    layout.leftToRight = -1;
                    layout.leftToLeft = -1;
                    layout.leftMargin = -1;
                    layout.goneLeftMargin = -1;
                    return;
                case 2:
                    Layout layout2 = constraint.layout;
                    layout2.rightToRight = -1;
                    layout2.rightToLeft = -1;
                    layout2.rightMargin = -1;
                    layout2.goneRightMargin = -1;
                    return;
                case 3:
                    Layout layout3 = constraint.layout;
                    layout3.topToBottom = -1;
                    layout3.topToTop = -1;
                    layout3.topMargin = -1;
                    layout3.goneTopMargin = -1;
                    return;
                case 4:
                    Layout layout4 = constraint.layout;
                    layout4.bottomToTop = -1;
                    layout4.bottomToBottom = -1;
                    layout4.bottomMargin = -1;
                    layout4.goneBottomMargin = -1;
                    return;
                case 5:
                    constraint.layout.baselineToBaseline = -1;
                    return;
                case 6:
                    Layout layout5 = constraint.layout;
                    layout5.startToEnd = -1;
                    layout5.startToStart = -1;
                    layout5.startMargin = -1;
                    layout5.goneStartMargin = -1;
                    return;
                case 7:
                    Layout layout6 = constraint.layout;
                    layout6.endToStart = -1;
                    layout6.endToEnd = -1;
                    layout6.endMargin = -1;
                    layout6.goneEndMargin = -1;
                    return;
                default:
                    throw new IllegalArgumentException("unknown constraint");
            }
        }
    }

    public void clone(ConstraintSet constraintSet) {
        this.mConstraints.clear();
        for (Integer num : constraintSet.mConstraints.keySet()) {
            this.mConstraints.put(num, constraintSet.mConstraints.get(num).m5727clone());
        }
    }

    public void centerHorizontally(int i2, int i3) {
        if (i3 == 0) {
            center(i2, 0, 1, 0, 0, 2, 0, 0.5f);
        } else {
            center(i2, i3, 2, 0, i3, 1, 0, 0.5f);
        }
    }

    public void centerHorizontallyRtl(int i2, int i3) {
        if (i3 == 0) {
            center(i2, 0, 6, 0, 0, 7, 0, 0.5f);
        } else {
            center(i2, i3, 7, 0, i3, 6, 0, 0.5f);
        }
    }

    public void centerVertically(int i2, int i3) {
        if (i3 == 0) {
            center(i2, 0, 3, 0, 0, 4, 0, 0.5f);
        } else {
            center(i2, i3, 4, 0, i3, 3, 0, 0.5f);
        }
    }

    public void clone(ConstraintLayout constraintLayout) {
        int childCount = constraintLayout.getChildCount();
        this.mConstraints.clear();
        for (int i2 = 0; i2 < childCount; i2++) {
            View childAt = constraintLayout.getChildAt(i2);
            ConstraintLayout.LayoutParams layoutParams = (ConstraintLayout.LayoutParams) childAt.getLayoutParams();
            int id = childAt.getId();
            if (this.mForceId && id == -1) {
                throw new RuntimeException("All children of ConstraintLayout must have ids to use ConstraintSet");
            }
            if (!this.mConstraints.containsKey(Integer.valueOf(id))) {
                this.mConstraints.put(Integer.valueOf(id), new Constraint());
            }
            Constraint constraint = this.mConstraints.get(Integer.valueOf(id));
            constraint.mCustomConstraints = ConstraintAttribute.extractAttributes(this.mSavedAttributes, childAt);
            constraint.fillFrom(id, layoutParams);
            constraint.propertySet.visibility = childAt.getVisibility();
            constraint.propertySet.alpha = childAt.getAlpha();
            constraint.transform.rotation = childAt.getRotation();
            constraint.transform.rotationX = childAt.getRotationX();
            constraint.transform.rotationY = childAt.getRotationY();
            constraint.transform.scaleX = childAt.getScaleX();
            constraint.transform.scaleY = childAt.getScaleY();
            float pivotX = childAt.getPivotX();
            float pivotY = childAt.getPivotY();
            if (pivotX != ShadowDrawableWrapper.COS_45 || pivotY != ShadowDrawableWrapper.COS_45) {
                Transform transform = constraint.transform;
                transform.transformPivotX = pivotX;
                transform.transformPivotY = pivotY;
            }
            constraint.transform.translationX = childAt.getTranslationX();
            constraint.transform.translationY = childAt.getTranslationY();
            constraint.transform.translationZ = childAt.getTranslationZ();
            Transform transform2 = constraint.transform;
            if (transform2.applyElevation) {
                transform2.elevation = childAt.getElevation();
            }
            if (childAt instanceof Barrier) {
                Barrier barrier = (Barrier) childAt;
                constraint.layout.mBarrierAllowsGoneWidgets = barrier.allowsGoneWidget();
                constraint.layout.mReferenceIds = barrier.getReferencedIds();
                constraint.layout.mBarrierDirection = barrier.getType();
                constraint.layout.mBarrierMargin = barrier.getMargin();
            }
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:63:0x0179, code lost:
    
        continue;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void load(android.content.Context r10, org.xmlpull.v1.XmlPullParser r11) {
        /*
            Method dump skipped, instructions count: 448
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.widget.ConstraintSet.load(android.content.Context, org.xmlpull.v1.XmlPullParser):void");
    }

    public void readFallback(ConstraintLayout constraintLayout) {
        int childCount = constraintLayout.getChildCount();
        for (int i2 = 0; i2 < childCount; i2++) {
            View childAt = constraintLayout.getChildAt(i2);
            ConstraintLayout.LayoutParams layoutParams = (ConstraintLayout.LayoutParams) childAt.getLayoutParams();
            int id = childAt.getId();
            if (this.mForceId && id == -1) {
                throw new RuntimeException("All children of ConstraintLayout must have ids to use ConstraintSet");
            }
            if (!this.mConstraints.containsKey(Integer.valueOf(id))) {
                this.mConstraints.put(Integer.valueOf(id), new Constraint());
            }
            Constraint constraint = this.mConstraints.get(Integer.valueOf(id));
            if (!constraint.layout.mApply) {
                constraint.fillFrom(id, layoutParams);
                if (childAt instanceof ConstraintHelper) {
                    constraint.layout.mReferenceIds = ((ConstraintHelper) childAt).getReferencedIds();
                    if (childAt instanceof Barrier) {
                        Barrier barrier = (Barrier) childAt;
                        constraint.layout.mBarrierAllowsGoneWidgets = barrier.allowsGoneWidget();
                        constraint.layout.mBarrierDirection = barrier.getType();
                        constraint.layout.mBarrierMargin = barrier.getMargin();
                    }
                }
                constraint.layout.mApply = true;
            }
            PropertySet propertySet = constraint.propertySet;
            if (!propertySet.mApply) {
                propertySet.visibility = childAt.getVisibility();
                constraint.propertySet.alpha = childAt.getAlpha();
                constraint.propertySet.mApply = true;
            }
            Transform transform = constraint.transform;
            if (!transform.mApply) {
                transform.mApply = true;
                transform.rotation = childAt.getRotation();
                constraint.transform.rotationX = childAt.getRotationX();
                constraint.transform.rotationY = childAt.getRotationY();
                constraint.transform.scaleX = childAt.getScaleX();
                constraint.transform.scaleY = childAt.getScaleY();
                float pivotX = childAt.getPivotX();
                float pivotY = childAt.getPivotY();
                if (pivotX != ShadowDrawableWrapper.COS_45 || pivotY != ShadowDrawableWrapper.COS_45) {
                    Transform transform2 = constraint.transform;
                    transform2.transformPivotX = pivotX;
                    transform2.transformPivotY = pivotY;
                }
                constraint.transform.translationX = childAt.getTranslationX();
                constraint.transform.translationY = childAt.getTranslationY();
                constraint.transform.translationZ = childAt.getTranslationZ();
                Transform transform3 = constraint.transform;
                if (transform3.applyElevation) {
                    transform3.elevation = childAt.getElevation();
                }
            }
        }
    }

    public void clone(Constraints constraints) {
        int childCount = constraints.getChildCount();
        this.mConstraints.clear();
        for (int i2 = 0; i2 < childCount; i2++) {
            View childAt = constraints.getChildAt(i2);
            Constraints.LayoutParams layoutParams = (Constraints.LayoutParams) childAt.getLayoutParams();
            int id = childAt.getId();
            if (this.mForceId && id == -1) {
                throw new RuntimeException("All children of ConstraintLayout must have ids to use ConstraintSet");
            }
            if (!this.mConstraints.containsKey(Integer.valueOf(id))) {
                this.mConstraints.put(Integer.valueOf(id), new Constraint());
            }
            Constraint constraint = this.mConstraints.get(Integer.valueOf(id));
            if (childAt instanceof ConstraintHelper) {
                constraint.fillFromConstraints((ConstraintHelper) childAt, id, layoutParams);
            }
            constraint.fillFromConstraints(id, layoutParams);
        }
    }

    public void connect(int i2, int i3, int i4, int i5) {
        if (!this.mConstraints.containsKey(Integer.valueOf(i2))) {
            this.mConstraints.put(Integer.valueOf(i2), new Constraint());
        }
        Constraint constraint = this.mConstraints.get(Integer.valueOf(i2));
        switch (i3) {
            case 1:
                if (i5 == 1) {
                    Layout layout = constraint.layout;
                    layout.leftToLeft = i4;
                    layout.leftToRight = -1;
                    return;
                } else {
                    if (i5 == 2) {
                        Layout layout2 = constraint.layout;
                        layout2.leftToRight = i4;
                        layout2.leftToLeft = -1;
                        return;
                    }
                    throw new IllegalArgumentException(C1499a.m582D(C1499a.m586H("left to "), sideToString(i5), " undefined"));
                }
            case 2:
                if (i5 == 1) {
                    Layout layout3 = constraint.layout;
                    layout3.rightToLeft = i4;
                    layout3.rightToRight = -1;
                    return;
                } else {
                    if (i5 == 2) {
                        Layout layout4 = constraint.layout;
                        layout4.rightToRight = i4;
                        layout4.rightToLeft = -1;
                        return;
                    }
                    throw new IllegalArgumentException(C1499a.m582D(C1499a.m586H("right to "), sideToString(i5), " undefined"));
                }
            case 3:
                if (i5 == 3) {
                    Layout layout5 = constraint.layout;
                    layout5.topToTop = i4;
                    layout5.topToBottom = -1;
                    layout5.baselineToBaseline = -1;
                    return;
                }
                if (i5 == 4) {
                    Layout layout6 = constraint.layout;
                    layout6.topToBottom = i4;
                    layout6.topToTop = -1;
                    layout6.baselineToBaseline = -1;
                    return;
                }
                throw new IllegalArgumentException(C1499a.m582D(C1499a.m586H("right to "), sideToString(i5), " undefined"));
            case 4:
                if (i5 == 4) {
                    Layout layout7 = constraint.layout;
                    layout7.bottomToBottom = i4;
                    layout7.bottomToTop = -1;
                    layout7.baselineToBaseline = -1;
                    return;
                }
                if (i5 == 3) {
                    Layout layout8 = constraint.layout;
                    layout8.bottomToTop = i4;
                    layout8.bottomToBottom = -1;
                    layout8.baselineToBaseline = -1;
                    return;
                }
                throw new IllegalArgumentException(C1499a.m582D(C1499a.m586H("right to "), sideToString(i5), " undefined"));
            case 5:
                if (i5 == 5) {
                    Layout layout9 = constraint.layout;
                    layout9.baselineToBaseline = i4;
                    layout9.bottomToBottom = -1;
                    layout9.bottomToTop = -1;
                    layout9.topToTop = -1;
                    layout9.topToBottom = -1;
                    return;
                }
                throw new IllegalArgumentException(C1499a.m582D(C1499a.m586H("right to "), sideToString(i5), " undefined"));
            case 6:
                if (i5 == 6) {
                    Layout layout10 = constraint.layout;
                    layout10.startToStart = i4;
                    layout10.startToEnd = -1;
                    return;
                } else {
                    if (i5 == 7) {
                        Layout layout11 = constraint.layout;
                        layout11.startToEnd = i4;
                        layout11.startToStart = -1;
                        return;
                    }
                    throw new IllegalArgumentException(C1499a.m582D(C1499a.m586H("right to "), sideToString(i5), " undefined"));
                }
            case 7:
                if (i5 == 7) {
                    Layout layout12 = constraint.layout;
                    layout12.endToEnd = i4;
                    layout12.endToStart = -1;
                    return;
                } else {
                    if (i5 == 6) {
                        Layout layout13 = constraint.layout;
                        layout13.endToStart = i4;
                        layout13.endToEnd = -1;
                        return;
                    }
                    throw new IllegalArgumentException(C1499a.m582D(C1499a.m586H("right to "), sideToString(i5), " undefined"));
                }
            default:
                StringBuilder sb = new StringBuilder();
                sb.append(sideToString(i3));
                sb.append(" to ");
                throw new IllegalArgumentException(C1499a.m582D(sb, sideToString(i5), " unknown"));
        }
    }
}
