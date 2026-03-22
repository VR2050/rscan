package kotlin.reflect.jvm.internal.impl.types;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.CollectionsKt__CollectionsJVMKt;
import kotlin.collections.CollectionsKt__CollectionsKt;
import kotlin.collections.CollectionsKt__IterablesKt;
import kotlin.collections.CollectionsKt__MutableCollectionsKt;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.jvm.JvmField;
import kotlin.jvm.internal.Intrinsics;
import kotlin.reflect.jvm.internal.impl.types.AbstractTypeCheckerContext;
import kotlin.reflect.jvm.internal.impl.types.model.ArgumentList;
import kotlin.reflect.jvm.internal.impl.types.model.CaptureStatus;
import kotlin.reflect.jvm.internal.impl.types.model.CapturedTypeMarker;
import kotlin.reflect.jvm.internal.impl.types.model.DefinitelyNotNullTypeMarker;
import kotlin.reflect.jvm.internal.impl.types.model.IntersectionTypeConstructorMarker;
import kotlin.reflect.jvm.internal.impl.types.model.KotlinTypeMarker;
import kotlin.reflect.jvm.internal.impl.types.model.SimpleTypeMarker;
import kotlin.reflect.jvm.internal.impl.types.model.TypeArgumentListMarker;
import kotlin.reflect.jvm.internal.impl.types.model.TypeArgumentMarker;
import kotlin.reflect.jvm.internal.impl.types.model.TypeConstructorMarker;
import kotlin.reflect.jvm.internal.impl.types.model.TypeParameterMarker;
import kotlin.reflect.jvm.internal.impl.types.model.TypeSystemContext;
import kotlin.reflect.jvm.internal.impl.types.model.TypeVariableTypeConstructorMarker;
import kotlin.reflect.jvm.internal.impl.types.model.TypeVariance;
import kotlin.reflect.jvm.internal.impl.utils.SmartList;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/* loaded from: classes.dex */
public final class AbstractTypeChecker {

    @NotNull
    public static final AbstractTypeChecker INSTANCE = new AbstractTypeChecker();

    @JvmField
    public static boolean RUN_SLOW_ASSERTIONS;

    public /* synthetic */ class WhenMappings {
        public static final /* synthetic */ int[] $EnumSwitchMapping$0;
        public static final /* synthetic */ int[] $EnumSwitchMapping$1;

        static {
            TypeVariance.values();
            int[] iArr = new int[3];
            iArr[TypeVariance.INV.ordinal()] = 1;
            iArr[TypeVariance.OUT.ordinal()] = 2;
            iArr[TypeVariance.IN.ordinal()] = 3;
            $EnumSwitchMapping$0 = iArr;
            AbstractTypeCheckerContext.LowerCapturedTypePolicy.values();
            int[] iArr2 = new int[3];
            iArr2[AbstractTypeCheckerContext.LowerCapturedTypePolicy.CHECK_ONLY_LOWER.ordinal()] = 1;
            iArr2[AbstractTypeCheckerContext.LowerCapturedTypePolicy.CHECK_SUBTYPE_AND_LOWER.ordinal()] = 2;
            iArr2[AbstractTypeCheckerContext.LowerCapturedTypePolicy.SKIP_LOWER.ordinal()] = 3;
            $EnumSwitchMapping$1 = iArr2;
        }
    }

    private AbstractTypeChecker() {
    }

    private final Boolean checkSubtypeForIntegerLiteralType(AbstractTypeCheckerContext abstractTypeCheckerContext, SimpleTypeMarker simpleTypeMarker, SimpleTypeMarker simpleTypeMarker2) {
        TypeSystemContext typeSystemContext = abstractTypeCheckerContext.getTypeSystemContext();
        if (!typeSystemContext.isIntegerLiteralType(simpleTypeMarker) && !typeSystemContext.isIntegerLiteralType(simpleTypeMarker2)) {
            return null;
        }
        if (typeSystemContext.isIntegerLiteralType(simpleTypeMarker) && typeSystemContext.isIntegerLiteralType(simpleTypeMarker2)) {
            return Boolean.TRUE;
        }
        if (typeSystemContext.isIntegerLiteralType(simpleTypeMarker)) {
            if (m5335xd35c7e25(typeSystemContext, abstractTypeCheckerContext, simpleTypeMarker, simpleTypeMarker2, false)) {
                return Boolean.TRUE;
            }
        } else if (typeSystemContext.isIntegerLiteralType(simpleTypeMarker2) && (m5334xabd2962a(typeSystemContext, simpleTypeMarker) || m5335xd35c7e25(typeSystemContext, abstractTypeCheckerContext, simpleTypeMarker2, simpleTypeMarker, true))) {
            return Boolean.TRUE;
        }
        return null;
    }

    /* renamed from: checkSubtypeForIntegerLiteralType$lambda-7$isIntegerLiteralTypeInIntersectionComponents */
    private static final boolean m5334xabd2962a(TypeSystemContext typeSystemContext, SimpleTypeMarker simpleTypeMarker) {
        boolean z;
        TypeConstructorMarker typeConstructor = typeSystemContext.typeConstructor(simpleTypeMarker);
        if (typeConstructor instanceof IntersectionTypeConstructorMarker) {
            Collection<KotlinTypeMarker> supertypes = typeSystemContext.supertypes(typeConstructor);
            if (!(supertypes instanceof Collection) || !supertypes.isEmpty()) {
                Iterator<T> it = supertypes.iterator();
                while (it.hasNext()) {
                    SimpleTypeMarker asSimpleType = typeSystemContext.asSimpleType((KotlinTypeMarker) it.next());
                    if (Intrinsics.areEqual(asSimpleType == null ? null : Boolean.valueOf(typeSystemContext.isIntegerLiteralType(asSimpleType)), Boolean.TRUE)) {
                        z = true;
                        break;
                    }
                }
            }
            z = false;
            if (z) {
                return true;
            }
        }
        return false;
    }

    /* renamed from: checkSubtypeForIntegerLiteralType$lambda-7$isTypeInIntegerLiteralType */
    private static final boolean m5335xd35c7e25(TypeSystemContext typeSystemContext, AbstractTypeCheckerContext abstractTypeCheckerContext, SimpleTypeMarker simpleTypeMarker, SimpleTypeMarker simpleTypeMarker2, boolean z) {
        Collection<KotlinTypeMarker> possibleIntegerTypes = typeSystemContext.possibleIntegerTypes(simpleTypeMarker);
        if (!(possibleIntegerTypes instanceof Collection) || !possibleIntegerTypes.isEmpty()) {
            for (KotlinTypeMarker kotlinTypeMarker : possibleIntegerTypes) {
                if (Intrinsics.areEqual(typeSystemContext.typeConstructor(kotlinTypeMarker), typeSystemContext.typeConstructor(simpleTypeMarker2)) || (z && isSubtypeOf$default(INSTANCE, abstractTypeCheckerContext, simpleTypeMarker2, kotlinTypeMarker, false, 8, null))) {
                    return true;
                }
            }
        }
        return false;
    }

    private final Boolean checkSubtypeForSpecialCases(AbstractTypeCheckerContext abstractTypeCheckerContext, SimpleTypeMarker simpleTypeMarker, SimpleTypeMarker simpleTypeMarker2) {
        SimpleTypeMarker simpleTypeMarker3;
        TypeParameterMarker typeParameterForArgumentInBaseIfItEqualToTarget;
        TypeSystemContext typeSystemContext = abstractTypeCheckerContext.getTypeSystemContext();
        boolean z = false;
        if (typeSystemContext.isError(simpleTypeMarker) || typeSystemContext.isError(simpleTypeMarker2)) {
            return abstractTypeCheckerContext.isErrorTypeEqualsToAnything() ? Boolean.TRUE : (!typeSystemContext.isMarkedNullable(simpleTypeMarker) || typeSystemContext.isMarkedNullable(simpleTypeMarker2)) ? Boolean.valueOf(AbstractStrictEqualityTypeChecker.INSTANCE.strictEqualTypes(typeSystemContext, typeSystemContext.withNullability(simpleTypeMarker, false), typeSystemContext.withNullability(simpleTypeMarker2, false))) : Boolean.FALSE;
        }
        if (typeSystemContext.isStubType(simpleTypeMarker) || typeSystemContext.isStubType(simpleTypeMarker2)) {
            return Boolean.valueOf(abstractTypeCheckerContext.isStubTypeEqualsToAnything());
        }
        DefinitelyNotNullTypeMarker asDefinitelyNotNullType = typeSystemContext.asDefinitelyNotNullType(simpleTypeMarker2);
        if (asDefinitelyNotNullType == null || (simpleTypeMarker3 = typeSystemContext.original(asDefinitelyNotNullType)) == null) {
            simpleTypeMarker3 = simpleTypeMarker2;
        }
        CapturedTypeMarker asCapturedType = typeSystemContext.asCapturedType(simpleTypeMarker3);
        KotlinTypeMarker lowerType = asCapturedType == null ? null : typeSystemContext.lowerType(asCapturedType);
        if (asCapturedType != null && lowerType != null) {
            if (typeSystemContext.isMarkedNullable(simpleTypeMarker2)) {
                lowerType = typeSystemContext.withNullability(lowerType, true);
            } else if (typeSystemContext.isDefinitelyNotNullType(simpleTypeMarker2)) {
                lowerType = typeSystemContext.makeDefinitelyNotNullOrNotNull(lowerType);
            }
            KotlinTypeMarker kotlinTypeMarker = lowerType;
            int ordinal = abstractTypeCheckerContext.getLowerCapturedTypePolicy(simpleTypeMarker, asCapturedType).ordinal();
            if (ordinal == 0) {
                return Boolean.valueOf(isSubtypeOf$default(INSTANCE, abstractTypeCheckerContext, simpleTypeMarker, kotlinTypeMarker, false, 8, null));
            }
            if (ordinal == 1 && isSubtypeOf$default(INSTANCE, abstractTypeCheckerContext, simpleTypeMarker, kotlinTypeMarker, false, 8, null)) {
                return Boolean.TRUE;
            }
        }
        TypeConstructorMarker typeConstructor = typeSystemContext.typeConstructor(simpleTypeMarker2);
        if (!typeSystemContext.isIntersection(typeConstructor)) {
            if ((simpleTypeMarker instanceof CapturedTypeMarker) && (typeParameterForArgumentInBaseIfItEqualToTarget = INSTANCE.getTypeParameterForArgumentInBaseIfItEqualToTarget(abstractTypeCheckerContext.getTypeSystemContext(), simpleTypeMarker2, simpleTypeMarker)) != null && typeSystemContext.hasRecursiveBounds(typeParameterForArgumentInBaseIfItEqualToTarget, typeSystemContext.typeConstructor(simpleTypeMarker2))) {
                return Boolean.TRUE;
            }
            return null;
        }
        typeSystemContext.isMarkedNullable(simpleTypeMarker2);
        Collection<KotlinTypeMarker> supertypes = typeSystemContext.supertypes(typeConstructor);
        if (!(supertypes instanceof Collection) || !supertypes.isEmpty()) {
            Iterator<T> it = supertypes.iterator();
            while (it.hasNext()) {
                if (!isSubtypeOf$default(INSTANCE, abstractTypeCheckerContext, simpleTypeMarker, (KotlinTypeMarker) it.next(), false, 8, null)) {
                    break;
                }
            }
        }
        z = true;
        return Boolean.valueOf(z);
    }

    private final List<SimpleTypeMarker> collectAllSupertypesWithGivenTypeConstructor(AbstractTypeCheckerContext abstractTypeCheckerContext, SimpleTypeMarker simpleTypeMarker, TypeConstructorMarker typeConstructorMarker) {
        AbstractTypeCheckerContext.SupertypesPolicy substitutionSupertypePolicy;
        TypeSystemContext typeSystemContext = abstractTypeCheckerContext.getTypeSystemContext();
        List<SimpleTypeMarker> fastCorrespondingSupertypes = typeSystemContext.fastCorrespondingSupertypes(simpleTypeMarker, typeConstructorMarker);
        if (fastCorrespondingSupertypes == null) {
            if (!typeSystemContext.isClassTypeConstructor(typeConstructorMarker) && typeSystemContext.isClassType(simpleTypeMarker)) {
                return CollectionsKt__CollectionsKt.emptyList();
            }
            if (typeSystemContext.isCommonFinalClassConstructor(typeConstructorMarker)) {
                if (!typeSystemContext.areEqualTypeConstructors(typeSystemContext.typeConstructor(simpleTypeMarker), typeConstructorMarker)) {
                    return CollectionsKt__CollectionsKt.emptyList();
                }
                SimpleTypeMarker captureFromArguments = typeSystemContext.captureFromArguments(simpleTypeMarker, CaptureStatus.FOR_SUBTYPING);
                if (captureFromArguments != null) {
                    simpleTypeMarker = captureFromArguments;
                }
                return CollectionsKt__CollectionsJVMKt.listOf(simpleTypeMarker);
            }
            fastCorrespondingSupertypes = new SmartList<>();
            abstractTypeCheckerContext.initialize();
            ArrayDeque<SimpleTypeMarker> supertypesDeque = abstractTypeCheckerContext.getSupertypesDeque();
            Intrinsics.checkNotNull(supertypesDeque);
            Set<SimpleTypeMarker> supertypesSet = abstractTypeCheckerContext.getSupertypesSet();
            Intrinsics.checkNotNull(supertypesSet);
            supertypesDeque.push(simpleTypeMarker);
            while (!supertypesDeque.isEmpty()) {
                if (supertypesSet.size() > 1000) {
                    throw new IllegalStateException(("Too many supertypes for type: " + simpleTypeMarker + ". Supertypes = " + CollectionsKt___CollectionsKt.joinToString$default(supertypesSet, null, null, null, 0, null, null, 63, null)).toString());
                }
                SimpleTypeMarker current = supertypesDeque.pop();
                Intrinsics.checkNotNullExpressionValue(current, "current");
                if (supertypesSet.add(current)) {
                    SimpleTypeMarker captureFromArguments2 = typeSystemContext.captureFromArguments(current, CaptureStatus.FOR_SUBTYPING);
                    if (captureFromArguments2 == null) {
                        captureFromArguments2 = current;
                    }
                    if (typeSystemContext.areEqualTypeConstructors(typeSystemContext.typeConstructor(captureFromArguments2), typeConstructorMarker)) {
                        fastCorrespondingSupertypes.add(captureFromArguments2);
                        substitutionSupertypePolicy = AbstractTypeCheckerContext.SupertypesPolicy.None.INSTANCE;
                    } else {
                        substitutionSupertypePolicy = typeSystemContext.argumentsCount(captureFromArguments2) == 0 ? AbstractTypeCheckerContext.SupertypesPolicy.LowerIfFlexible.INSTANCE : abstractTypeCheckerContext.substitutionSupertypePolicy(captureFromArguments2);
                    }
                    if (!(!Intrinsics.areEqual(substitutionSupertypePolicy, AbstractTypeCheckerContext.SupertypesPolicy.None.INSTANCE))) {
                        substitutionSupertypePolicy = null;
                    }
                    if (substitutionSupertypePolicy != null) {
                        TypeSystemContext typeSystemContext2 = abstractTypeCheckerContext.getTypeSystemContext();
                        Iterator<KotlinTypeMarker> it = typeSystemContext2.supertypes(typeSystemContext2.typeConstructor(current)).iterator();
                        while (it.hasNext()) {
                            supertypesDeque.add(substitutionSupertypePolicy.mo7315transformType(abstractTypeCheckerContext, it.next()));
                        }
                    }
                }
            }
            abstractTypeCheckerContext.clear();
        }
        return fastCorrespondingSupertypes;
    }

    private final List<SimpleTypeMarker> collectAndFilter(AbstractTypeCheckerContext abstractTypeCheckerContext, SimpleTypeMarker simpleTypeMarker, TypeConstructorMarker typeConstructorMarker) {
        return selectOnlyPureKotlinSupertypes(abstractTypeCheckerContext, collectAllSupertypesWithGivenTypeConstructor(abstractTypeCheckerContext, simpleTypeMarker, typeConstructorMarker));
    }

    private final boolean completeIsSubTypeOf(AbstractTypeCheckerContext abstractTypeCheckerContext, KotlinTypeMarker kotlinTypeMarker, KotlinTypeMarker kotlinTypeMarker2, boolean z) {
        TypeSystemContext typeSystemContext = abstractTypeCheckerContext.getTypeSystemContext();
        KotlinTypeMarker prepareType = abstractTypeCheckerContext.prepareType(abstractTypeCheckerContext.refineType(kotlinTypeMarker));
        KotlinTypeMarker prepareType2 = abstractTypeCheckerContext.prepareType(abstractTypeCheckerContext.refineType(kotlinTypeMarker2));
        AbstractTypeChecker abstractTypeChecker = INSTANCE;
        Boolean checkSubtypeForSpecialCases = abstractTypeChecker.checkSubtypeForSpecialCases(abstractTypeCheckerContext, typeSystemContext.lowerBoundIfFlexible(prepareType), typeSystemContext.upperBoundIfFlexible(prepareType2));
        if (checkSubtypeForSpecialCases == null) {
            Boolean addSubtypeConstraint = abstractTypeCheckerContext.addSubtypeConstraint(prepareType, prepareType2, z);
            return addSubtypeConstraint == null ? abstractTypeChecker.isSubtypeOfForSingleClassifierType(abstractTypeCheckerContext, typeSystemContext.lowerBoundIfFlexible(prepareType), typeSystemContext.upperBoundIfFlexible(prepareType2)) : addSubtypeConstraint.booleanValue();
        }
        boolean booleanValue = checkSubtypeForSpecialCases.booleanValue();
        abstractTypeCheckerContext.addSubtypeConstraint(prepareType, prepareType2, z);
        return booleanValue;
    }

    private final TypeParameterMarker getTypeParameterForArgumentInBaseIfItEqualToTarget(TypeSystemContext typeSystemContext, KotlinTypeMarker kotlinTypeMarker, KotlinTypeMarker kotlinTypeMarker2) {
        int argumentsCount = typeSystemContext.argumentsCount(kotlinTypeMarker);
        if (argumentsCount > 0) {
            int i2 = 0;
            while (true) {
                int i3 = i2 + 1;
                TypeArgumentMarker argument = typeSystemContext.getArgument(kotlinTypeMarker, i2);
                if (!(!typeSystemContext.isStarProjection(argument))) {
                    argument = null;
                }
                if (argument != null) {
                    if (Intrinsics.areEqual(typeSystemContext.getType(argument), kotlinTypeMarker2)) {
                        return typeSystemContext.getParameter(typeSystemContext.typeConstructor(kotlinTypeMarker), i2);
                    }
                    TypeParameterMarker typeParameterForArgumentInBaseIfItEqualToTarget = getTypeParameterForArgumentInBaseIfItEqualToTarget(typeSystemContext, typeSystemContext.getType(argument), kotlinTypeMarker2);
                    if (typeParameterForArgumentInBaseIfItEqualToTarget != null) {
                        return typeParameterForArgumentInBaseIfItEqualToTarget;
                    }
                }
                if (i3 >= argumentsCount) {
                    break;
                }
                i2 = i3;
            }
        }
        return null;
    }

    private final boolean hasNothingSupertype(AbstractTypeCheckerContext abstractTypeCheckerContext, SimpleTypeMarker simpleTypeMarker) {
        TypeSystemContext typeSystemContext = abstractTypeCheckerContext.getTypeSystemContext();
        TypeConstructorMarker typeConstructor = typeSystemContext.typeConstructor(simpleTypeMarker);
        if (typeSystemContext.isClassTypeConstructor(typeConstructor)) {
            return typeSystemContext.isNothingConstructor(typeConstructor);
        }
        if (typeSystemContext.isNothingConstructor(typeSystemContext.typeConstructor(simpleTypeMarker))) {
            return true;
        }
        abstractTypeCheckerContext.initialize();
        ArrayDeque<SimpleTypeMarker> supertypesDeque = abstractTypeCheckerContext.getSupertypesDeque();
        Intrinsics.checkNotNull(supertypesDeque);
        Set<SimpleTypeMarker> supertypesSet = abstractTypeCheckerContext.getSupertypesSet();
        Intrinsics.checkNotNull(supertypesSet);
        supertypesDeque.push(simpleTypeMarker);
        while (!supertypesDeque.isEmpty()) {
            if (supertypesSet.size() > 1000) {
                throw new IllegalStateException(("Too many supertypes for type: " + simpleTypeMarker + ". Supertypes = " + CollectionsKt___CollectionsKt.joinToString$default(supertypesSet, null, null, null, 0, null, null, 63, null)).toString());
            }
            SimpleTypeMarker current = supertypesDeque.pop();
            Intrinsics.checkNotNullExpressionValue(current, "current");
            if (supertypesSet.add(current)) {
                AbstractTypeCheckerContext.SupertypesPolicy supertypesPolicy = typeSystemContext.isClassType(current) ? AbstractTypeCheckerContext.SupertypesPolicy.None.INSTANCE : AbstractTypeCheckerContext.SupertypesPolicy.LowerIfFlexible.INSTANCE;
                if (!(!Intrinsics.areEqual(supertypesPolicy, AbstractTypeCheckerContext.SupertypesPolicy.None.INSTANCE))) {
                    supertypesPolicy = null;
                }
                if (supertypesPolicy == null) {
                    continue;
                } else {
                    TypeSystemContext typeSystemContext2 = abstractTypeCheckerContext.getTypeSystemContext();
                    Iterator<KotlinTypeMarker> it = typeSystemContext2.supertypes(typeSystemContext2.typeConstructor(current)).iterator();
                    while (it.hasNext()) {
                        SimpleTypeMarker mo7315transformType = supertypesPolicy.mo7315transformType(abstractTypeCheckerContext, it.next());
                        if (typeSystemContext.isNothingConstructor(typeSystemContext.typeConstructor(mo7315transformType))) {
                            abstractTypeCheckerContext.clear();
                            return true;
                        }
                        supertypesDeque.add(mo7315transformType);
                    }
                }
            }
        }
        abstractTypeCheckerContext.clear();
        return false;
    }

    private final boolean isCommonDenotableType(TypeSystemContext typeSystemContext, KotlinTypeMarker kotlinTypeMarker) {
        return typeSystemContext.isDenotable(typeSystemContext.typeConstructor(kotlinTypeMarker)) && !typeSystemContext.isDynamic(kotlinTypeMarker) && !typeSystemContext.isDefinitelyNotNullType(kotlinTypeMarker) && Intrinsics.areEqual(typeSystemContext.typeConstructor(typeSystemContext.lowerBoundIfFlexible(kotlinTypeMarker)), typeSystemContext.typeConstructor(typeSystemContext.upperBoundIfFlexible(kotlinTypeMarker)));
    }

    public static /* synthetic */ boolean isSubtypeOf$default(AbstractTypeChecker abstractTypeChecker, AbstractTypeCheckerContext abstractTypeCheckerContext, KotlinTypeMarker kotlinTypeMarker, KotlinTypeMarker kotlinTypeMarker2, boolean z, int i2, Object obj) {
        if ((i2 & 8) != 0) {
            z = false;
        }
        return abstractTypeChecker.isSubtypeOf(abstractTypeCheckerContext, kotlinTypeMarker, kotlinTypeMarker2, z);
    }

    private final boolean isSubtypeOfForSingleClassifierType(AbstractTypeCheckerContext abstractTypeCheckerContext, SimpleTypeMarker simpleTypeMarker, SimpleTypeMarker simpleTypeMarker2) {
        boolean z;
        TypeConstructorMarker typeConstructorMarker;
        TypeConstructorMarker typeConstructorMarker2;
        TypeSystemContext typeSystemContext = abstractTypeCheckerContext.getTypeSystemContext();
        if (RUN_SLOW_ASSERTIONS) {
            if (!typeSystemContext.isSingleClassifierType(simpleTypeMarker) && !typeSystemContext.isIntersection(typeSystemContext.typeConstructor(simpleTypeMarker))) {
                abstractTypeCheckerContext.isAllowedTypeVariableBridge(simpleTypeMarker);
            }
            if (!typeSystemContext.isSingleClassifierType(simpleTypeMarker2)) {
                abstractTypeCheckerContext.isAllowedTypeVariableBridge(simpleTypeMarker2);
            }
        }
        if (!AbstractNullabilityChecker.INSTANCE.isPossibleSubtype(abstractTypeCheckerContext, simpleTypeMarker, simpleTypeMarker2)) {
            return false;
        }
        AbstractTypeChecker abstractTypeChecker = INSTANCE;
        Boolean checkSubtypeForIntegerLiteralType = abstractTypeChecker.checkSubtypeForIntegerLiteralType(abstractTypeCheckerContext, typeSystemContext.lowerBoundIfFlexible(simpleTypeMarker), typeSystemContext.upperBoundIfFlexible(simpleTypeMarker2));
        if (checkSubtypeForIntegerLiteralType != null) {
            boolean booleanValue = checkSubtypeForIntegerLiteralType.booleanValue();
            AbstractTypeCheckerContext.addSubtypeConstraint$default(abstractTypeCheckerContext, simpleTypeMarker, simpleTypeMarker2, false, 4, null);
            return booleanValue;
        }
        TypeConstructorMarker typeConstructor = typeSystemContext.typeConstructor(simpleTypeMarker2);
        if ((typeSystemContext.areEqualTypeConstructors(typeSystemContext.typeConstructor(simpleTypeMarker), typeConstructor) && typeSystemContext.parametersCount(typeConstructor) == 0) || typeSystemContext.isAnyConstructor(typeSystemContext.typeConstructor(simpleTypeMarker2))) {
            return true;
        }
        List<SimpleTypeMarker> findCorrespondingSupertypes = abstractTypeChecker.findCorrespondingSupertypes(abstractTypeCheckerContext, simpleTypeMarker, typeConstructor);
        int i2 = 10;
        ArrayList<SimpleTypeMarker> arrayList = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(findCorrespondingSupertypes, 10));
        for (SimpleTypeMarker simpleTypeMarker3 : findCorrespondingSupertypes) {
            SimpleTypeMarker asSimpleType = typeSystemContext.asSimpleType(abstractTypeCheckerContext.prepareType(simpleTypeMarker3));
            if (asSimpleType != null) {
                simpleTypeMarker3 = asSimpleType;
            }
            arrayList.add(simpleTypeMarker3);
        }
        int size = arrayList.size();
        if (size == 0) {
            return INSTANCE.hasNothingSupertype(abstractTypeCheckerContext, simpleTypeMarker);
        }
        if (size == 1) {
            return INSTANCE.isSubtypeForSameConstructor(abstractTypeCheckerContext, typeSystemContext.asArgumentList((SimpleTypeMarker) CollectionsKt___CollectionsKt.first((List) arrayList)), simpleTypeMarker2);
        }
        ArgumentList argumentList = new ArgumentList(typeSystemContext.parametersCount(typeConstructor));
        int parametersCount = typeSystemContext.parametersCount(typeConstructor);
        if (parametersCount > 0) {
            int i3 = 0;
            z = false;
            while (true) {
                int i4 = i3 + 1;
                z = z || typeSystemContext.getVariance(typeSystemContext.getParameter(typeConstructor, i3)) != TypeVariance.OUT;
                if (z) {
                    typeConstructorMarker = typeConstructor;
                } else {
                    ArrayList arrayList2 = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(arrayList, i2));
                    for (SimpleTypeMarker simpleTypeMarker4 : arrayList) {
                        TypeArgumentMarker argumentOrNull = typeSystemContext.getArgumentOrNull(simpleTypeMarker4, i3);
                        KotlinTypeMarker kotlinTypeMarker = null;
                        if (argumentOrNull == null) {
                            typeConstructorMarker2 = typeConstructor;
                        } else {
                            typeConstructorMarker2 = typeConstructor;
                            if (!(typeSystemContext.getVariance(argumentOrNull) == TypeVariance.INV)) {
                                argumentOrNull = null;
                            }
                            if (argumentOrNull != null) {
                                kotlinTypeMarker = typeSystemContext.getType(argumentOrNull);
                            }
                        }
                        KotlinTypeMarker kotlinTypeMarker2 = kotlinTypeMarker;
                        if (kotlinTypeMarker2 == null) {
                            throw new IllegalStateException(("Incorrect type: " + simpleTypeMarker4 + ", subType: " + simpleTypeMarker + ", superType: " + simpleTypeMarker2).toString());
                        }
                        arrayList2.add(kotlinTypeMarker2);
                        typeConstructor = typeConstructorMarker2;
                    }
                    typeConstructorMarker = typeConstructor;
                    argumentList.add(typeSystemContext.asTypeArgument(typeSystemContext.intersectTypes(arrayList2)));
                }
                if (i4 >= parametersCount) {
                    break;
                }
                i3 = i4;
                typeConstructor = typeConstructorMarker;
                i2 = 10;
            }
        } else {
            z = false;
        }
        if (!z && INSTANCE.isSubtypeForSameConstructor(abstractTypeCheckerContext, argumentList, simpleTypeMarker2)) {
            return true;
        }
        if (!arrayList.isEmpty()) {
            Iterator it = arrayList.iterator();
            while (it.hasNext()) {
                if (INSTANCE.isSubtypeForSameConstructor(abstractTypeCheckerContext, typeSystemContext.asArgumentList((SimpleTypeMarker) it.next()), simpleTypeMarker2)) {
                    return true;
                }
            }
        }
        return false;
    }

    private final boolean isTypeVariableAgainstStarProjectionForSelfType(TypeSystemContext typeSystemContext, KotlinTypeMarker kotlinTypeMarker, KotlinTypeMarker kotlinTypeMarker2, TypeConstructorMarker typeConstructorMarker) {
        SimpleTypeMarker asSimpleType = typeSystemContext.asSimpleType(kotlinTypeMarker);
        if (asSimpleType instanceof CapturedTypeMarker) {
            CapturedTypeMarker capturedTypeMarker = (CapturedTypeMarker) asSimpleType;
            if (!typeSystemContext.isStarProjection(typeSystemContext.projection(typeSystemContext.typeConstructor(capturedTypeMarker))) || typeSystemContext.captureStatus(capturedTypeMarker) != CaptureStatus.FOR_SUBTYPING) {
                return false;
            }
            TypeConstructorMarker typeConstructor = typeSystemContext.typeConstructor(kotlinTypeMarker2);
            TypeVariableTypeConstructorMarker typeVariableTypeConstructorMarker = typeConstructor instanceof TypeVariableTypeConstructorMarker ? (TypeVariableTypeConstructorMarker) typeConstructor : null;
            if (typeVariableTypeConstructorMarker == null) {
                return false;
            }
            TypeParameterMarker typeParameter = typeSystemContext.getTypeParameter(typeVariableTypeConstructorMarker);
            return Intrinsics.areEqual(typeParameter != null ? Boolean.valueOf(typeSystemContext.hasRecursiveBounds(typeParameter, typeConstructorMarker)) : null, Boolean.TRUE);
        }
        return false;
    }

    /* JADX WARN: Multi-variable type inference failed */
    private final List<SimpleTypeMarker> selectOnlyPureKotlinSupertypes(AbstractTypeCheckerContext abstractTypeCheckerContext, List<? extends SimpleTypeMarker> list) {
        TypeSystemContext typeSystemContext = abstractTypeCheckerContext.getTypeSystemContext();
        if (list.size() < 2) {
            return list;
        }
        ArrayList arrayList = new ArrayList();
        Iterator it = list.iterator();
        while (true) {
            boolean z = true;
            if (!it.hasNext()) {
                break;
            }
            Object next = it.next();
            TypeArgumentListMarker asArgumentList = typeSystemContext.asArgumentList((SimpleTypeMarker) next);
            int size = typeSystemContext.size(asArgumentList);
            int i2 = 0;
            while (true) {
                if (i2 >= size) {
                    break;
                }
                if (!(typeSystemContext.asFlexibleType(typeSystemContext.getType(typeSystemContext.get(asArgumentList, i2))) == null)) {
                    z = false;
                    break;
                }
                i2++;
            }
            if (z) {
                arrayList.add(next);
            }
        }
        return arrayList.isEmpty() ^ true ? arrayList : list;
    }

    @Nullable
    public final TypeVariance effectiveVariance(@NotNull TypeVariance declared, @NotNull TypeVariance useSite) {
        Intrinsics.checkNotNullParameter(declared, "declared");
        Intrinsics.checkNotNullParameter(useSite, "useSite");
        TypeVariance typeVariance = TypeVariance.INV;
        if (declared == typeVariance) {
            return useSite;
        }
        if (useSite == typeVariance || declared == useSite) {
            return declared;
        }
        return null;
    }

    public final boolean equalTypes(@NotNull AbstractTypeCheckerContext context, @NotNull KotlinTypeMarker a, @NotNull KotlinTypeMarker b2) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(a, "a");
        Intrinsics.checkNotNullParameter(b2, "b");
        TypeSystemContext typeSystemContext = context.getTypeSystemContext();
        if (a == b2) {
            return true;
        }
        AbstractTypeChecker abstractTypeChecker = INSTANCE;
        if (abstractTypeChecker.isCommonDenotableType(typeSystemContext, a) && abstractTypeChecker.isCommonDenotableType(typeSystemContext, b2)) {
            KotlinTypeMarker refineType = context.refineType(a);
            KotlinTypeMarker refineType2 = context.refineType(b2);
            SimpleTypeMarker lowerBoundIfFlexible = typeSystemContext.lowerBoundIfFlexible(refineType);
            if (!typeSystemContext.areEqualTypeConstructors(typeSystemContext.typeConstructor(refineType), typeSystemContext.typeConstructor(refineType2))) {
                return false;
            }
            if (typeSystemContext.argumentsCount(lowerBoundIfFlexible) == 0) {
                return typeSystemContext.hasFlexibleNullability(refineType) || typeSystemContext.hasFlexibleNullability(refineType2) || typeSystemContext.isMarkedNullable(lowerBoundIfFlexible) == typeSystemContext.isMarkedNullable(typeSystemContext.lowerBoundIfFlexible(refineType2));
            }
        }
        return isSubtypeOf$default(abstractTypeChecker, context, a, b2, false, 8, null) && isSubtypeOf$default(abstractTypeChecker, context, b2, a, false, 8, null);
    }

    @NotNull
    public final List<SimpleTypeMarker> findCorrespondingSupertypes(@NotNull AbstractTypeCheckerContext context, @NotNull SimpleTypeMarker subType, @NotNull TypeConstructorMarker superConstructor) {
        AbstractTypeCheckerContext.SupertypesPolicy supertypesPolicy;
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(subType, "subType");
        Intrinsics.checkNotNullParameter(superConstructor, "superConstructor");
        TypeSystemContext typeSystemContext = context.getTypeSystemContext();
        if (typeSystemContext.isClassType(subType)) {
            return INSTANCE.collectAndFilter(context, subType, superConstructor);
        }
        if (!typeSystemContext.isClassTypeConstructor(superConstructor) && !typeSystemContext.isIntegerLiteralTypeConstructor(superConstructor)) {
            return INSTANCE.collectAllSupertypesWithGivenTypeConstructor(context, subType, superConstructor);
        }
        SmartList<SimpleTypeMarker> smartList = new SmartList();
        context.initialize();
        ArrayDeque<SimpleTypeMarker> supertypesDeque = context.getSupertypesDeque();
        Intrinsics.checkNotNull(supertypesDeque);
        Set<SimpleTypeMarker> supertypesSet = context.getSupertypesSet();
        Intrinsics.checkNotNull(supertypesSet);
        supertypesDeque.push(subType);
        while (!supertypesDeque.isEmpty()) {
            if (supertypesSet.size() > 1000) {
                throw new IllegalStateException(("Too many supertypes for type: " + subType + ". Supertypes = " + CollectionsKt___CollectionsKt.joinToString$default(supertypesSet, null, null, null, 0, null, null, 63, null)).toString());
            }
            SimpleTypeMarker current = supertypesDeque.pop();
            Intrinsics.checkNotNullExpressionValue(current, "current");
            if (supertypesSet.add(current)) {
                if (typeSystemContext.isClassType(current)) {
                    smartList.add(current);
                    supertypesPolicy = AbstractTypeCheckerContext.SupertypesPolicy.None.INSTANCE;
                } else {
                    supertypesPolicy = AbstractTypeCheckerContext.SupertypesPolicy.LowerIfFlexible.INSTANCE;
                }
                if (!(!Intrinsics.areEqual(supertypesPolicy, AbstractTypeCheckerContext.SupertypesPolicy.None.INSTANCE))) {
                    supertypesPolicy = null;
                }
                if (supertypesPolicy != null) {
                    TypeSystemContext typeSystemContext2 = context.getTypeSystemContext();
                    Iterator<KotlinTypeMarker> it = typeSystemContext2.supertypes(typeSystemContext2.typeConstructor(current)).iterator();
                    while (it.hasNext()) {
                        supertypesDeque.add(supertypesPolicy.mo7315transformType(context, it.next()));
                    }
                }
            }
        }
        context.clear();
        ArrayList arrayList = new ArrayList();
        for (SimpleTypeMarker it2 : smartList) {
            AbstractTypeChecker abstractTypeChecker = INSTANCE;
            Intrinsics.checkNotNullExpressionValue(it2, "it");
            CollectionsKt__MutableCollectionsKt.addAll(arrayList, abstractTypeChecker.collectAndFilter(context, it2, superConstructor));
        }
        return arrayList;
    }

    public final boolean isSubtypeForSameConstructor(@NotNull AbstractTypeCheckerContext abstractTypeCheckerContext, @NotNull TypeArgumentListMarker capturedSubArguments, @NotNull SimpleTypeMarker superType) {
        int i2;
        int i3;
        boolean isSubtypeOf$default;
        int i4;
        Intrinsics.checkNotNullParameter(abstractTypeCheckerContext, "<this>");
        Intrinsics.checkNotNullParameter(capturedSubArguments, "capturedSubArguments");
        Intrinsics.checkNotNullParameter(superType, "superType");
        TypeSystemContext typeSystemContext = abstractTypeCheckerContext.getTypeSystemContext();
        TypeConstructorMarker typeConstructor = typeSystemContext.typeConstructor(superType);
        int size = typeSystemContext.size(capturedSubArguments);
        int parametersCount = typeSystemContext.parametersCount(typeConstructor);
        if (size != parametersCount || size != typeSystemContext.argumentsCount(superType)) {
            return false;
        }
        if (parametersCount > 0) {
            int i5 = 0;
            while (true) {
                int i6 = i5 + 1;
                TypeArgumentMarker argument = typeSystemContext.getArgument(superType, i5);
                if (!typeSystemContext.isStarProjection(argument)) {
                    KotlinTypeMarker type = typeSystemContext.getType(argument);
                    TypeArgumentMarker typeArgumentMarker = typeSystemContext.get(capturedSubArguments, i5);
                    typeSystemContext.getVariance(typeArgumentMarker);
                    TypeVariance typeVariance = TypeVariance.INV;
                    KotlinTypeMarker type2 = typeSystemContext.getType(typeArgumentMarker);
                    AbstractTypeChecker abstractTypeChecker = INSTANCE;
                    TypeVariance effectiveVariance = abstractTypeChecker.effectiveVariance(typeSystemContext.getVariance(typeSystemContext.getParameter(typeConstructor, i5)), typeSystemContext.getVariance(argument));
                    if (effectiveVariance == null) {
                        return abstractTypeCheckerContext.isErrorTypeEqualsToAnything();
                    }
                    if (!(effectiveVariance == typeVariance && (abstractTypeChecker.isTypeVariableAgainstStarProjectionForSelfType(typeSystemContext, type2, type, typeConstructor) || abstractTypeChecker.isTypeVariableAgainstStarProjectionForSelfType(typeSystemContext, type, type2, typeConstructor)))) {
                        i2 = abstractTypeCheckerContext.argumentsDepth;
                        if (i2 > 100) {
                            throw new IllegalStateException(Intrinsics.stringPlus("Arguments depth is too high. Some related argument: ", type2).toString());
                        }
                        i3 = abstractTypeCheckerContext.argumentsDepth;
                        abstractTypeCheckerContext.argumentsDepth = i3 + 1;
                        int ordinal = effectiveVariance.ordinal();
                        if (ordinal == 0) {
                            isSubtypeOf$default = isSubtypeOf$default(abstractTypeChecker, abstractTypeCheckerContext, type, type2, false, 8, null);
                        } else if (ordinal == 1) {
                            isSubtypeOf$default = isSubtypeOf$default(abstractTypeChecker, abstractTypeCheckerContext, type2, type, false, 8, null);
                        } else {
                            if (ordinal != 2) {
                                throw new NoWhenBranchMatchedException();
                            }
                            isSubtypeOf$default = abstractTypeChecker.equalTypes(abstractTypeCheckerContext, type2, type);
                        }
                        i4 = abstractTypeCheckerContext.argumentsDepth;
                        abstractTypeCheckerContext.argumentsDepth = i4 - 1;
                        if (!isSubtypeOf$default) {
                            return false;
                        }
                    }
                }
                if (i6 >= parametersCount) {
                    break;
                }
                i5 = i6;
            }
        }
        return true;
    }

    public final boolean isSubtypeOf(@NotNull AbstractTypeCheckerContext context, @NotNull KotlinTypeMarker subType, @NotNull KotlinTypeMarker superType, boolean z) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(subType, "subType");
        Intrinsics.checkNotNullParameter(superType, "superType");
        if (subType == superType) {
            return true;
        }
        if (context.customIsSubtypeOf(subType, superType)) {
            return completeIsSubTypeOf(context, subType, superType, z);
        }
        return false;
    }
}
