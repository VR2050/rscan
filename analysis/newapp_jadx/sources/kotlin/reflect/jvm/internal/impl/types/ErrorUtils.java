package kotlin.reflect.jvm.internal.impl.types;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import kotlin.collections.CollectionsKt__CollectionsKt;
import kotlin.jvm.functions.Function1;
import kotlin.reflect.jvm.internal.impl.builtins.DefaultBuiltIns;
import kotlin.reflect.jvm.internal.impl.builtins.KotlinBuiltIns;
import kotlin.reflect.jvm.internal.impl.descriptors.CallableMemberDescriptor;
import kotlin.reflect.jvm.internal.impl.descriptors.ClassDescriptor;
import kotlin.reflect.jvm.internal.impl.descriptors.ClassifierDescriptor;
import kotlin.reflect.jvm.internal.impl.descriptors.DeclarationDescriptor;
import kotlin.reflect.jvm.internal.impl.descriptors.DeclarationDescriptorVisitor;
import kotlin.reflect.jvm.internal.impl.descriptors.DescriptorVisibilities;
import kotlin.reflect.jvm.internal.impl.descriptors.Modality;
import kotlin.reflect.jvm.internal.impl.descriptors.ModuleCapability;
import kotlin.reflect.jvm.internal.impl.descriptors.ModuleDescriptor;
import kotlin.reflect.jvm.internal.impl.descriptors.PackageViewDescriptor;
import kotlin.reflect.jvm.internal.impl.descriptors.PropertyDescriptor;
import kotlin.reflect.jvm.internal.impl.descriptors.ReceiverParameterDescriptor;
import kotlin.reflect.jvm.internal.impl.descriptors.SimpleFunctionDescriptor;
import kotlin.reflect.jvm.internal.impl.descriptors.SourceElement;
import kotlin.reflect.jvm.internal.impl.descriptors.TypeParameterDescriptor;
import kotlin.reflect.jvm.internal.impl.descriptors.annotations.Annotations;
import kotlin.reflect.jvm.internal.impl.descriptors.impl.ClassDescriptorImpl;
import kotlin.reflect.jvm.internal.impl.descriptors.impl.PropertyDescriptorImpl;
import kotlin.reflect.jvm.internal.impl.incremental.components.LookupLocation;
import kotlin.reflect.jvm.internal.impl.name.FqName;
import kotlin.reflect.jvm.internal.impl.name.Name;
import kotlin.reflect.jvm.internal.impl.resolve.descriptorUtil.DescriptorUtilsKt;
import kotlin.reflect.jvm.internal.impl.resolve.scopes.DescriptorKindFilter;
import kotlin.reflect.jvm.internal.impl.resolve.scopes.MemberScope;
import kotlin.reflect.jvm.internal.impl.types.checker.KotlinTypeRefiner;
import kotlin.reflect.jvm.internal.impl.types.error.ErrorSimpleFunctionDescriptorImpl;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public class ErrorUtils {
    private static final PropertyDescriptor ERROR_PROPERTY;
    private static final Set<PropertyDescriptor> ERROR_PROPERTY_GROUP;
    private static final ModuleDescriptor ERROR_MODULE = new ModuleDescriptor() { // from class: kotlin.reflect.jvm.internal.impl.types.ErrorUtils.1
        /* JADX WARN: Removed duplicated region for block: B:18:0x002c  */
        /* JADX WARN: Removed duplicated region for block: B:21:0x0037  */
        /* JADX WARN: Removed duplicated region for block: B:24:0x0056  */
        /* JADX WARN: Removed duplicated region for block: B:32:0x0093  */
        /* JADX WARN: Removed duplicated region for block: B:33:0x0098  */
        /* JADX WARN: Removed duplicated region for block: B:34:0x009d  */
        /* JADX WARN: Removed duplicated region for block: B:35:0x00a2  */
        /* JADX WARN: Removed duplicated region for block: B:36:0x00a7  */
        /* JADX WARN: Removed duplicated region for block: B:39:0x00af A[ADDED_TO_REGION] */
        /* JADX WARN: Removed duplicated region for block: B:45:0x00bc  */
        /* JADX WARN: Removed duplicated region for block: B:58:0x008c  */
        /* JADX WARN: Removed duplicated region for block: B:59:0x003c  */
        /* JADX WARN: Removed duplicated region for block: B:60:0x0041  */
        /* JADX WARN: Removed duplicated region for block: B:61:0x0046  */
        /* JADX WARN: Removed duplicated region for block: B:62:0x004b  */
        /* JADX WARN: Removed duplicated region for block: B:63:0x0050  */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        private static /* synthetic */ void $$$reportNull$$$0(int r12) {
            /*
                Method dump skipped, instructions count: 304
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: kotlin.reflect.jvm.internal.impl.types.ErrorUtils.C47121.$$$reportNull$$$0(int):void");
        }

        @Override // kotlin.reflect.jvm.internal.impl.descriptors.DeclarationDescriptor
        public <R, D> R accept(@NotNull DeclarationDescriptorVisitor<R, D> declarationDescriptorVisitor, D d2) {
            if (declarationDescriptorVisitor != null) {
                return null;
            }
            $$$reportNull$$$0(11);
            return null;
        }

        @Override // kotlin.reflect.jvm.internal.impl.descriptors.annotations.Annotated
        @NotNull
        public Annotations getAnnotations() {
            Annotations empty = Annotations.Companion.getEMPTY();
            if (empty == null) {
                $$$reportNull$$$0(1);
            }
            return empty;
        }

        @Override // kotlin.reflect.jvm.internal.impl.descriptors.ModuleDescriptor
        @NotNull
        public KotlinBuiltIns getBuiltIns() {
            DefaultBuiltIns defaultBuiltIns = DefaultBuiltIns.getInstance();
            if (defaultBuiltIns == null) {
                $$$reportNull$$$0(14);
            }
            return defaultBuiltIns;
        }

        @Override // kotlin.reflect.jvm.internal.impl.descriptors.ModuleDescriptor
        @Nullable
        public <T> T getCapability(@NotNull ModuleCapability<T> moduleCapability) {
            if (moduleCapability != null) {
                return null;
            }
            $$$reportNull$$$0(0);
            return null;
        }

        @Override // kotlin.reflect.jvm.internal.impl.descriptors.DeclarationDescriptor
        @Nullable
        public DeclarationDescriptor getContainingDeclaration() {
            return null;
        }

        @Override // kotlin.reflect.jvm.internal.impl.descriptors.ModuleDescriptor
        @NotNull
        public List<ModuleDescriptor> getExpectedByModules() {
            List<ModuleDescriptor> emptyList = CollectionsKt__CollectionsKt.emptyList();
            if (emptyList == null) {
                $$$reportNull$$$0(9);
            }
            return emptyList;
        }

        @Override // kotlin.reflect.jvm.internal.impl.descriptors.Named
        @NotNull
        public Name getName() {
            Name special = Name.special("<ERROR MODULE>");
            if (special == null) {
                $$$reportNull$$$0(5);
            }
            return special;
        }

        @Override // kotlin.reflect.jvm.internal.impl.descriptors.DeclarationDescriptor
        @NotNull
        public DeclarationDescriptor getOriginal() {
            return this;
        }

        @Override // kotlin.reflect.jvm.internal.impl.descriptors.ModuleDescriptor
        @NotNull
        public PackageViewDescriptor getPackage(@NotNull FqName fqName) {
            if (fqName == null) {
                $$$reportNull$$$0(7);
            }
            throw new IllegalStateException("Should not be called!");
        }

        @Override // kotlin.reflect.jvm.internal.impl.descriptors.ModuleDescriptor
        @NotNull
        public Collection<FqName> getSubPackagesOf(@NotNull FqName fqName, @NotNull Function1<? super Name, Boolean> function1) {
            if (fqName == null) {
                $$$reportNull$$$0(2);
            }
            if (function1 == null) {
                $$$reportNull$$$0(3);
            }
            List emptyList = CollectionsKt__CollectionsKt.emptyList();
            if (emptyList == null) {
                $$$reportNull$$$0(4);
            }
            return emptyList;
        }

        @Override // kotlin.reflect.jvm.internal.impl.descriptors.ModuleDescriptor
        public boolean shouldSeeInternalsOf(@NotNull ModuleDescriptor moduleDescriptor) {
            if (moduleDescriptor != null) {
                return false;
            }
            $$$reportNull$$$0(12);
            return false;
        }
    };
    private static final ErrorClassDescriptor ERROR_CLASS = new ErrorClassDescriptor(Name.special("<ERROR CLASS>"));
    public static final SimpleType ERROR_TYPE_FOR_LOOP_IN_SUPERTYPES = createErrorType("<LOOP IN SUPERTYPES>");
    private static final KotlinType ERROR_PROPERTY_TYPE = createErrorType("<ERROR PROPERTY TYPE>");

    public static class ErrorClassDescriptor extends ClassDescriptorImpl {
        private static /* synthetic */ void $$$reportNull$$$0(int i2) {
            String str = (i2 == 2 || i2 == 5 || i2 == 8) ? "@NotNull method %s.%s must not return null" : "Argument for @NotNull parameter '%s' of %s.%s must not be null";
            Object[] objArr = new Object[(i2 == 2 || i2 == 5 || i2 == 8) ? 2 : 3];
            switch (i2) {
                case 1:
                    objArr[0] = "substitutor";
                    break;
                case 2:
                case 5:
                case 8:
                    objArr[0] = "kotlin/reflect/jvm/internal/impl/types/ErrorUtils$ErrorClassDescriptor";
                    break;
                case 3:
                    objArr[0] = "typeArguments";
                    break;
                case 4:
                case 7:
                    objArr[0] = "kotlinTypeRefiner";
                    break;
                case 6:
                    objArr[0] = "typeSubstitution";
                    break;
                default:
                    objArr[0] = "name";
                    break;
            }
            if (i2 == 2) {
                objArr[1] = "substitute";
            } else if (i2 == 5 || i2 == 8) {
                objArr[1] = "getMemberScope";
            } else {
                objArr[1] = "kotlin/reflect/jvm/internal/impl/types/ErrorUtils$ErrorClassDescriptor";
            }
            switch (i2) {
                case 1:
                    objArr[2] = "substitute";
                    break;
                case 2:
                case 5:
                case 8:
                    break;
                case 3:
                case 4:
                case 6:
                case 7:
                    objArr[2] = "getMemberScope";
                    break;
                default:
                    objArr[2] = "<init>";
                    break;
            }
            String format = String.format(str, objArr);
            if (i2 != 2 && i2 != 5 && i2 != 8) {
                throw new IllegalArgumentException(format);
            }
            throw new IllegalStateException(format);
        }

        /* JADX WARN: Illegal instructions before constructor call */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public ErrorClassDescriptor(@org.jetbrains.annotations.NotNull kotlin.reflect.jvm.internal.impl.name.Name r11) {
            /*
                r10 = this;
                if (r11 != 0) goto L6
                r0 = 0
                $$$reportNull$$$0(r0)
            L6:
                kotlin.reflect.jvm.internal.impl.descriptors.ModuleDescriptor r2 = kotlin.reflect.jvm.internal.impl.types.ErrorUtils.getErrorModule()
                kotlin.reflect.jvm.internal.impl.descriptors.Modality r4 = kotlin.reflect.jvm.internal.impl.descriptors.Modality.OPEN
                kotlin.reflect.jvm.internal.impl.descriptors.ClassKind r5 = kotlin.reflect.jvm.internal.impl.descriptors.ClassKind.CLASS
                java.util.List r6 = java.util.Collections.emptyList()
                kotlin.reflect.jvm.internal.impl.descriptors.SourceElement r0 = kotlin.reflect.jvm.internal.impl.descriptors.SourceElement.NO_SOURCE
                r8 = 0
                kotlin.reflect.jvm.internal.impl.storage.StorageManager r9 = kotlin.reflect.jvm.internal.impl.storage.LockBasedStorageManager.NO_LOCKS
                r1 = r10
                r3 = r11
                r7 = r0
                r1.<init>(r2, r3, r4, r5, r6, r7, r8, r9)
                kotlin.reflect.jvm.internal.impl.descriptors.annotations.Annotations$Companion r11 = kotlin.reflect.jvm.internal.impl.descriptors.annotations.Annotations.Companion
                kotlin.reflect.jvm.internal.impl.descriptors.annotations.Annotations r11 = r11.getEMPTY()
                r1 = 1
                kotlin.reflect.jvm.internal.impl.descriptors.impl.ClassConstructorDescriptorImpl r11 = kotlin.reflect.jvm.internal.impl.descriptors.impl.ClassConstructorDescriptorImpl.create(r10, r11, r1, r0)
                java.util.List r0 = java.util.Collections.emptyList()
                kotlin.reflect.jvm.internal.impl.descriptors.DescriptorVisibility r1 = kotlin.reflect.jvm.internal.impl.descriptors.DescriptorVisibilities.INTERNAL
                r11.initialize(r0, r1)
                kotlin.reflect.jvm.internal.impl.name.Name r0 = r10.getName()
                java.lang.String r0 = r0.asString()
                kotlin.reflect.jvm.internal.impl.resolve.scopes.MemberScope r0 = kotlin.reflect.jvm.internal.impl.types.ErrorUtils.createErrorScope(r0)
                kotlin.reflect.jvm.internal.impl.types.ErrorType r1 = new kotlin.reflect.jvm.internal.impl.types.ErrorType
                java.lang.String r2 = "<ERROR>"
                kotlin.reflect.jvm.internal.impl.types.TypeConstructor r2 = kotlin.reflect.jvm.internal.impl.types.ErrorUtils.access$200(r2, r10)
                r1.<init>(r2, r0)
                r11.setReturnType(r1)
                java.util.Set r1 = java.util.Collections.singleton(r11)
                r10.initialize(r0, r1, r11)
                return
            */
            throw new UnsupportedOperationException("Method not decompiled: kotlin.reflect.jvm.internal.impl.types.ErrorUtils.ErrorClassDescriptor.<init>(kotlin.reflect.jvm.internal.impl.name.Name):void");
        }

        @Override // kotlin.reflect.jvm.internal.impl.descriptors.impl.AbstractClassDescriptor, kotlin.reflect.jvm.internal.impl.descriptors.impl.ModuleAwareClassDescriptor
        @NotNull
        public MemberScope getMemberScope(@NotNull TypeSubstitution typeSubstitution, @NotNull KotlinTypeRefiner kotlinTypeRefiner) {
            if (typeSubstitution == null) {
                $$$reportNull$$$0(6);
            }
            if (kotlinTypeRefiner == null) {
                $$$reportNull$$$0(7);
            }
            StringBuilder m586H = C1499a.m586H("Error scope for class ");
            m586H.append(getName());
            m586H.append(" with arguments: ");
            m586H.append(typeSubstitution);
            MemberScope createErrorScope = ErrorUtils.createErrorScope(m586H.toString());
            if (createErrorScope == null) {
                $$$reportNull$$$0(8);
            }
            return createErrorScope;
        }

        @Override // kotlin.reflect.jvm.internal.impl.descriptors.impl.AbstractClassDescriptor, kotlin.reflect.jvm.internal.impl.descriptors.Substitutable
        @NotNull
        public ClassDescriptor substitute(@NotNull TypeSubstitutor typeSubstitutor) {
            if (typeSubstitutor == null) {
                $$$reportNull$$$0(1);
            }
            return this;
        }

        @Override // kotlin.reflect.jvm.internal.impl.descriptors.impl.ClassDescriptorImpl
        public String toString() {
            return getName().asString();
        }
    }

    public static class ErrorScope implements MemberScope {
        private final String debugMessage;

        /* JADX WARN: Removed duplicated region for block: B:10:0x0017  */
        /* JADX WARN: Removed duplicated region for block: B:13:0x0022  */
        /* JADX WARN: Removed duplicated region for block: B:16:0x004b  */
        /* JADX WARN: Removed duplicated region for block: B:20:0x006d  */
        /* JADX WARN: Removed duplicated region for block: B:21:0x0072  */
        /* JADX WARN: Removed duplicated region for block: B:22:0x0077  */
        /* JADX WARN: Removed duplicated region for block: B:23:0x007c  */
        /* JADX WARN: Removed duplicated region for block: B:24:0x007f  */
        /* JADX WARN: Removed duplicated region for block: B:25:0x0084  */
        /* JADX WARN: Removed duplicated region for block: B:26:0x0087  */
        /* JADX WARN: Removed duplicated region for block: B:27:0x008a  */
        /* JADX WARN: Removed duplicated region for block: B:28:0x008f  */
        /* JADX WARN: Removed duplicated region for block: B:31:0x0099 A[ADDED_TO_REGION] */
        /* JADX WARN: Removed duplicated region for block: B:33:0x009e  */
        /* JADX WARN: Removed duplicated region for block: B:43:0x0068  */
        /* JADX WARN: Removed duplicated region for block: B:44:0x0027  */
        /* JADX WARN: Removed duplicated region for block: B:45:0x002c  */
        /* JADX WARN: Removed duplicated region for block: B:46:0x0031  */
        /* JADX WARN: Removed duplicated region for block: B:47:0x0036  */
        /* JADX WARN: Removed duplicated region for block: B:48:0x0039  */
        /* JADX WARN: Removed duplicated region for block: B:49:0x003e  */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        private static /* synthetic */ void $$$reportNull$$$0(int r10) {
            /*
                r0 = 18
                r1 = 7
                if (r10 == r1) goto Ld
                if (r10 == r0) goto Ld
                switch(r10) {
                    case 10: goto Ld;
                    case 11: goto Ld;
                    case 12: goto Ld;
                    case 13: goto Ld;
                    default: goto La;
                }
            La:
                java.lang.String r2 = "Argument for @NotNull parameter '%s' of %s.%s must not be null"
                goto Lf
            Ld:
                java.lang.String r2 = "@NotNull method %s.%s must not return null"
            Lf:
                r3 = 2
                if (r10 == r1) goto L19
                if (r10 == r0) goto L19
                switch(r10) {
                    case 10: goto L19;
                    case 11: goto L19;
                    case 12: goto L19;
                    case 13: goto L19;
                    default: goto L17;
                }
            L17:
                r4 = 3
                goto L1a
            L19:
                r4 = 2
            L1a:
                java.lang.Object[] r4 = new java.lang.Object[r4]
                java.lang.String r5 = "kotlin/reflect/jvm/internal/impl/types/ErrorUtils$ErrorScope"
                r6 = 0
                switch(r10) {
                    case 1: goto L3e;
                    case 2: goto L39;
                    case 3: goto L3e;
                    case 4: goto L39;
                    case 5: goto L3e;
                    case 6: goto L39;
                    case 7: goto L36;
                    case 8: goto L3e;
                    case 9: goto L39;
                    case 10: goto L36;
                    case 11: goto L36;
                    case 12: goto L36;
                    case 13: goto L36;
                    case 14: goto L3e;
                    case 15: goto L39;
                    case 16: goto L31;
                    case 17: goto L2c;
                    case 18: goto L36;
                    case 19: goto L3e;
                    case 20: goto L27;
                    default: goto L22;
                }
            L22:
                java.lang.String r7 = "debugMessage"
                r4[r6] = r7
                goto L42
            L27:
                java.lang.String r7 = "p"
                r4[r6] = r7
                goto L42
            L2c:
                java.lang.String r7 = "nameFilter"
                r4[r6] = r7
                goto L42
            L31:
                java.lang.String r7 = "kindFilter"
                r4[r6] = r7
                goto L42
            L36:
                r4[r6] = r5
                goto L42
            L39:
                java.lang.String r7 = "location"
                r4[r6] = r7
                goto L42
            L3e:
                java.lang.String r7 = "name"
                r4[r6] = r7
            L42:
                java.lang.String r6 = "getContributedDescriptors"
                java.lang.String r7 = "getContributedFunctions"
                java.lang.String r8 = "getContributedVariables"
                r9 = 1
                if (r10 == r1) goto L68
                if (r10 == r0) goto L65
                switch(r10) {
                    case 10: goto L62;
                    case 11: goto L5d;
                    case 12: goto L58;
                    case 13: goto L53;
                    default: goto L50;
                }
            L50:
                r4[r9] = r5
                goto L6a
            L53:
                java.lang.String r5 = "getClassifierNames"
                r4[r9] = r5
                goto L6a
            L58:
                java.lang.String r5 = "getVariableNames"
                r4[r9] = r5
                goto L6a
            L5d:
                java.lang.String r5 = "getFunctionNames"
                r4[r9] = r5
                goto L6a
            L62:
                r4[r9] = r7
                goto L6a
            L65:
                r4[r9] = r6
                goto L6a
            L68:
                r4[r9] = r8
            L6a:
                switch(r10) {
                    case 1: goto L8f;
                    case 2: goto L8f;
                    case 3: goto L8a;
                    case 4: goto L8a;
                    case 5: goto L87;
                    case 6: goto L87;
                    case 7: goto L93;
                    case 8: goto L84;
                    case 9: goto L84;
                    case 10: goto L93;
                    case 11: goto L93;
                    case 12: goto L93;
                    case 13: goto L93;
                    case 14: goto L7f;
                    case 15: goto L7f;
                    case 16: goto L7c;
                    case 17: goto L7c;
                    case 18: goto L93;
                    case 19: goto L77;
                    case 20: goto L72;
                    default: goto L6d;
                }
            L6d:
                java.lang.String r5 = "<init>"
                r4[r3] = r5
                goto L93
            L72:
                java.lang.String r5 = "printScopeStructure"
                r4[r3] = r5
                goto L93
            L77:
                java.lang.String r5 = "definitelyDoesNotContainName"
                r4[r3] = r5
                goto L93
            L7c:
                r4[r3] = r6
                goto L93
            L7f:
                java.lang.String r5 = "recordLookup"
                r4[r3] = r5
                goto L93
            L84:
                r4[r3] = r7
                goto L93
            L87:
                r4[r3] = r8
                goto L93
            L8a:
                java.lang.String r5 = "getContributedClassifierIncludeDeprecated"
                r4[r3] = r5
                goto L93
            L8f:
                java.lang.String r5 = "getContributedClassifier"
                r4[r3] = r5
            L93:
                java.lang.String r2 = java.lang.String.format(r2, r4)
                if (r10 == r1) goto La4
                if (r10 == r0) goto La4
                switch(r10) {
                    case 10: goto La4;
                    case 11: goto La4;
                    case 12: goto La4;
                    case 13: goto La4;
                    default: goto L9e;
                }
            L9e:
                java.lang.IllegalArgumentException r10 = new java.lang.IllegalArgumentException
                r10.<init>(r2)
                goto La9
            La4:
                java.lang.IllegalStateException r10 = new java.lang.IllegalStateException
                r10.<init>(r2)
            La9:
                throw r10
            */
            throw new UnsupportedOperationException("Method not decompiled: kotlin.reflect.jvm.internal.impl.types.ErrorUtils.ErrorScope.$$$reportNull$$$0(int):void");
        }

        @Override // kotlin.reflect.jvm.internal.impl.resolve.scopes.MemberScope
        @NotNull
        public Set<Name> getClassifierNames() {
            Set<Name> emptySet = Collections.emptySet();
            if (emptySet == null) {
                $$$reportNull$$$0(13);
            }
            return emptySet;
        }

        @Override // kotlin.reflect.jvm.internal.impl.resolve.scopes.ResolutionScope
        @Nullable
        /* renamed from: getContributedClassifier */
        public ClassifierDescriptor mo7313getContributedClassifier(@NotNull Name name, @NotNull LookupLocation lookupLocation) {
            if (name == null) {
                $$$reportNull$$$0(1);
            }
            if (lookupLocation == null) {
                $$$reportNull$$$0(2);
            }
            return ErrorUtils.createErrorClass(name.asString());
        }

        @Override // kotlin.reflect.jvm.internal.impl.resolve.scopes.ResolutionScope
        @NotNull
        public Collection<DeclarationDescriptor> getContributedDescriptors(@NotNull DescriptorKindFilter descriptorKindFilter, @NotNull Function1<? super Name, Boolean> function1) {
            if (descriptorKindFilter == null) {
                $$$reportNull$$$0(16);
            }
            if (function1 == null) {
                $$$reportNull$$$0(17);
            }
            List emptyList = Collections.emptyList();
            if (emptyList == null) {
                $$$reportNull$$$0(18);
            }
            return emptyList;
        }

        @Override // kotlin.reflect.jvm.internal.impl.resolve.scopes.MemberScope
        @NotNull
        public Set<Name> getFunctionNames() {
            Set<Name> emptySet = Collections.emptySet();
            if (emptySet == null) {
                $$$reportNull$$$0(11);
            }
            return emptySet;
        }

        @Override // kotlin.reflect.jvm.internal.impl.resolve.scopes.MemberScope
        @NotNull
        public Set<Name> getVariableNames() {
            Set<Name> emptySet = Collections.emptySet();
            if (emptySet == null) {
                $$$reportNull$$$0(12);
            }
            return emptySet;
        }

        @Override // kotlin.reflect.jvm.internal.impl.resolve.scopes.ResolutionScope
        public void recordLookup(@NotNull Name name, @NotNull LookupLocation lookupLocation) {
            if (name == null) {
                $$$reportNull$$$0(14);
            }
            if (lookupLocation == null) {
                $$$reportNull$$$0(15);
            }
        }

        public String toString() {
            return C1499a.m581C(C1499a.m586H("ErrorScope{"), this.debugMessage, '}');
        }

        private ErrorScope(@NotNull String str) {
            if (str == null) {
                $$$reportNull$$$0(0);
            }
            this.debugMessage = str;
        }

        @Override // kotlin.reflect.jvm.internal.impl.resolve.scopes.MemberScope, kotlin.reflect.jvm.internal.impl.resolve.scopes.ResolutionScope
        @NotNull
        public Set<? extends SimpleFunctionDescriptor> getContributedFunctions(@NotNull Name name, @NotNull LookupLocation lookupLocation) {
            if (name == null) {
                $$$reportNull$$$0(8);
            }
            if (lookupLocation == null) {
                $$$reportNull$$$0(9);
            }
            Set<? extends SimpleFunctionDescriptor> singleton = Collections.singleton(ErrorUtils.createErrorFunction(this));
            if (singleton == null) {
                $$$reportNull$$$0(10);
            }
            return singleton;
        }

        @Override // kotlin.reflect.jvm.internal.impl.resolve.scopes.MemberScope
        @NotNull
        public Set<? extends PropertyDescriptor> getContributedVariables(@NotNull Name name, @NotNull LookupLocation lookupLocation) {
            if (name == null) {
                $$$reportNull$$$0(5);
            }
            if (lookupLocation == null) {
                $$$reportNull$$$0(6);
            }
            Set<? extends PropertyDescriptor> set = ErrorUtils.ERROR_PROPERTY_GROUP;
            if (set == null) {
                $$$reportNull$$$0(7);
            }
            return set;
        }
    }

    public static class ThrowingScope implements MemberScope {
        private final String debugMessage;

        private static /* synthetic */ void $$$reportNull$$$0(int i2) {
            Object[] objArr = new Object[3];
            switch (i2) {
                case 1:
                case 3:
                case 5:
                case 7:
                case 11:
                case 13:
                    objArr[0] = "name";
                    break;
                case 2:
                case 4:
                case 6:
                case 8:
                case 12:
                    objArr[0] = "location";
                    break;
                case 9:
                    objArr[0] = "kindFilter";
                    break;
                case 10:
                    objArr[0] = "nameFilter";
                    break;
                case 14:
                    objArr[0] = "p";
                    break;
                default:
                    objArr[0] = "message";
                    break;
            }
            objArr[1] = "kotlin/reflect/jvm/internal/impl/types/ErrorUtils$ThrowingScope";
            switch (i2) {
                case 1:
                case 2:
                    objArr[2] = "getContributedClassifier";
                    break;
                case 3:
                case 4:
                    objArr[2] = "getContributedClassifierIncludeDeprecated";
                    break;
                case 5:
                case 6:
                    objArr[2] = "getContributedVariables";
                    break;
                case 7:
                case 8:
                    objArr[2] = "getContributedFunctions";
                    break;
                case 9:
                case 10:
                    objArr[2] = "getContributedDescriptors";
                    break;
                case 11:
                case 12:
                    objArr[2] = "recordLookup";
                    break;
                case 13:
                    objArr[2] = "definitelyDoesNotContainName";
                    break;
                case 14:
                    objArr[2] = "printScopeStructure";
                    break;
                default:
                    objArr[2] = "<init>";
                    break;
            }
            throw new IllegalArgumentException(String.format("Argument for @NotNull parameter '%s' of %s.%s must not be null", objArr));
        }

        @Override // kotlin.reflect.jvm.internal.impl.resolve.scopes.MemberScope
        public Set<Name> getClassifierNames() {
            throw new IllegalStateException();
        }

        @Override // kotlin.reflect.jvm.internal.impl.resolve.scopes.ResolutionScope
        @Nullable
        /* renamed from: getContributedClassifier */
        public ClassifierDescriptor mo7313getContributedClassifier(@NotNull Name name, @NotNull LookupLocation lookupLocation) {
            if (name == null) {
                $$$reportNull$$$0(1);
            }
            if (lookupLocation == null) {
                $$$reportNull$$$0(2);
            }
            throw new IllegalStateException(this.debugMessage + ", required name: " + name);
        }

        @Override // kotlin.reflect.jvm.internal.impl.resolve.scopes.ResolutionScope
        @NotNull
        public Collection<DeclarationDescriptor> getContributedDescriptors(@NotNull DescriptorKindFilter descriptorKindFilter, @NotNull Function1<? super Name, Boolean> function1) {
            if (descriptorKindFilter == null) {
                $$$reportNull$$$0(9);
            }
            if (function1 == null) {
                $$$reportNull$$$0(10);
            }
            throw new IllegalStateException(this.debugMessage);
        }

        @Override // kotlin.reflect.jvm.internal.impl.resolve.scopes.MemberScope, kotlin.reflect.jvm.internal.impl.resolve.scopes.ResolutionScope
        @NotNull
        public Collection<? extends SimpleFunctionDescriptor> getContributedFunctions(@NotNull Name name, @NotNull LookupLocation lookupLocation) {
            if (name == null) {
                $$$reportNull$$$0(7);
            }
            if (lookupLocation == null) {
                $$$reportNull$$$0(8);
            }
            throw new IllegalStateException(this.debugMessage + ", required name: " + name);
        }

        @Override // kotlin.reflect.jvm.internal.impl.resolve.scopes.MemberScope
        @NotNull
        public Collection<? extends PropertyDescriptor> getContributedVariables(@NotNull Name name, @NotNull LookupLocation lookupLocation) {
            if (name == null) {
                $$$reportNull$$$0(5);
            }
            if (lookupLocation == null) {
                $$$reportNull$$$0(6);
            }
            throw new IllegalStateException(this.debugMessage + ", required name: " + name);
        }

        @Override // kotlin.reflect.jvm.internal.impl.resolve.scopes.MemberScope
        @NotNull
        public Set<Name> getFunctionNames() {
            throw new IllegalStateException();
        }

        @Override // kotlin.reflect.jvm.internal.impl.resolve.scopes.MemberScope
        @NotNull
        public Set<Name> getVariableNames() {
            throw new IllegalStateException();
        }

        @Override // kotlin.reflect.jvm.internal.impl.resolve.scopes.ResolutionScope
        public void recordLookup(@NotNull Name name, @NotNull LookupLocation lookupLocation) {
            if (name == null) {
                $$$reportNull$$$0(11);
            }
            if (lookupLocation == null) {
                $$$reportNull$$$0(12);
            }
            throw new IllegalStateException();
        }

        public String toString() {
            return C1499a.m581C(C1499a.m586H("ThrowingScope{"), this.debugMessage, '}');
        }

        private ThrowingScope(@NotNull String str) {
            if (str == null) {
                $$$reportNull$$$0(0);
            }
            this.debugMessage = str;
        }
    }

    public static class UninferredParameterTypeConstructor implements TypeConstructor {
        private final TypeConstructor errorTypeConstructor;
        private final TypeParameterDescriptor typeParameterDescriptor;

        private static /* synthetic */ void $$$reportNull$$$0(int i2) {
            String str = (i2 == 1 || i2 == 2 || i2 == 3 || i2 == 4 || i2 == 6) ? "@NotNull method %s.%s must not return null" : "Argument for @NotNull parameter '%s' of %s.%s must not be null";
            Object[] objArr = new Object[(i2 == 1 || i2 == 2 || i2 == 3 || i2 == 4 || i2 == 6) ? 2 : 3];
            switch (i2) {
                case 1:
                case 2:
                case 3:
                case 4:
                case 6:
                    objArr[0] = "kotlin/reflect/jvm/internal/impl/types/ErrorUtils$UninferredParameterTypeConstructor";
                    break;
                case 5:
                    objArr[0] = "kotlinTypeRefiner";
                    break;
                default:
                    objArr[0] = "descriptor";
                    break;
            }
            if (i2 == 1) {
                objArr[1] = "getTypeParameterDescriptor";
            } else if (i2 == 2) {
                objArr[1] = "getParameters";
            } else if (i2 == 3) {
                objArr[1] = "getSupertypes";
            } else if (i2 == 4) {
                objArr[1] = "getBuiltIns";
            } else if (i2 != 6) {
                objArr[1] = "kotlin/reflect/jvm/internal/impl/types/ErrorUtils$UninferredParameterTypeConstructor";
            } else {
                objArr[1] = "refine";
            }
            switch (i2) {
                case 1:
                case 2:
                case 3:
                case 4:
                case 6:
                    break;
                case 5:
                    objArr[2] = "refine";
                    break;
                default:
                    objArr[2] = "<init>";
                    break;
            }
            String format = String.format(str, objArr);
            if (i2 != 1 && i2 != 2 && i2 != 3 && i2 != 4 && i2 != 6) {
                throw new IllegalArgumentException(format);
            }
            throw new IllegalStateException(format);
        }

        @Override // kotlin.reflect.jvm.internal.impl.types.TypeConstructor
        @NotNull
        public KotlinBuiltIns getBuiltIns() {
            KotlinBuiltIns builtIns = DescriptorUtilsKt.getBuiltIns(this.typeParameterDescriptor);
            if (builtIns == null) {
                $$$reportNull$$$0(4);
            }
            return builtIns;
        }

        @Override // kotlin.reflect.jvm.internal.impl.types.TypeConstructor
        @Nullable
        /* renamed from: getDeclarationDescriptor */
        public ClassifierDescriptor mo7311getDeclarationDescriptor() {
            return this.errorTypeConstructor.mo7311getDeclarationDescriptor();
        }

        @Override // kotlin.reflect.jvm.internal.impl.types.TypeConstructor
        @NotNull
        public List<TypeParameterDescriptor> getParameters() {
            List<TypeParameterDescriptor> parameters = this.errorTypeConstructor.getParameters();
            if (parameters == null) {
                $$$reportNull$$$0(2);
            }
            return parameters;
        }

        @Override // kotlin.reflect.jvm.internal.impl.types.TypeConstructor
        @NotNull
        /* renamed from: getSupertypes */
        public Collection<KotlinType> mo7312getSupertypes() {
            Collection<KotlinType> mo7312getSupertypes = this.errorTypeConstructor.mo7312getSupertypes();
            if (mo7312getSupertypes == null) {
                $$$reportNull$$$0(3);
            }
            return mo7312getSupertypes;
        }

        @NotNull
        public TypeParameterDescriptor getTypeParameterDescriptor() {
            TypeParameterDescriptor typeParameterDescriptor = this.typeParameterDescriptor;
            if (typeParameterDescriptor == null) {
                $$$reportNull$$$0(1);
            }
            return typeParameterDescriptor;
        }

        @Override // kotlin.reflect.jvm.internal.impl.types.TypeConstructor
        public boolean isDenotable() {
            return this.errorTypeConstructor.isDenotable();
        }

        @Override // kotlin.reflect.jvm.internal.impl.types.TypeConstructor
        @NotNull
        public TypeConstructor refine(@NotNull KotlinTypeRefiner kotlinTypeRefiner) {
            if (kotlinTypeRefiner == null) {
                $$$reportNull$$$0(5);
            }
            return this;
        }
    }

    private static /* synthetic */ void $$$reportNull$$$0(int i2) {
        String str = (i2 == 4 || i2 == 6 || i2 == 19) ? "@NotNull method %s.%s must not return null" : "Argument for @NotNull parameter '%s' of %s.%s must not be null";
        Object[] objArr = new Object[(i2 == 4 || i2 == 6 || i2 == 19) ? 2 : 3];
        switch (i2) {
            case 1:
            case 2:
            case 3:
            case 7:
            case 11:
            case 15:
                objArr[0] = "debugMessage";
                break;
            case 4:
            case 6:
            case 19:
                objArr[0] = "kotlin/reflect/jvm/internal/impl/types/ErrorUtils";
                break;
            case 5:
                objArr[0] = "ownerScope";
                break;
            case 8:
            case 9:
            case 16:
            case 17:
                objArr[0] = "debugName";
                break;
            case 10:
                objArr[0] = "typeConstructor";
                break;
            case 12:
            case 14:
                objArr[0] = "arguments";
                break;
            case 13:
                objArr[0] = "presentableName";
                break;
            case 18:
                objArr[0] = "errorClass";
                break;
            case 20:
                objArr[0] = "typeParameterDescriptor";
                break;
            default:
                objArr[0] = "function";
                break;
        }
        if (i2 == 4) {
            objArr[1] = "createErrorProperty";
        } else if (i2 == 6) {
            objArr[1] = "createErrorFunction";
        } else if (i2 != 19) {
            objArr[1] = "kotlin/reflect/jvm/internal/impl/types/ErrorUtils";
        } else {
            objArr[1] = "getErrorModule";
        }
        switch (i2) {
            case 1:
                objArr[2] = "createErrorClass";
                break;
            case 2:
            case 3:
                objArr[2] = "createErrorScope";
                break;
            case 4:
            case 6:
            case 19:
                break;
            case 5:
                objArr[2] = "createErrorFunction";
                break;
            case 7:
                objArr[2] = "createErrorType";
                break;
            case 8:
                objArr[2] = "createErrorTypeWithCustomDebugName";
                break;
            case 9:
            case 10:
                objArr[2] = "createErrorTypeWithCustomConstructor";
                break;
            case 11:
            case 12:
                objArr[2] = "createErrorTypeWithArguments";
                break;
            case 13:
            case 14:
                objArr[2] = "createUnresolvedType";
                break;
            case 15:
                objArr[2] = "createErrorTypeConstructor";
                break;
            case 16:
            case 17:
            case 18:
                objArr[2] = "createErrorTypeConstructorWithCustomDebugName";
                break;
            case 20:
                objArr[2] = "createUninferredParameterType";
                break;
            default:
                objArr[2] = "containsErrorTypeInParameters";
                break;
        }
        String format = String.format(str, objArr);
        if (i2 != 4 && i2 != 6 && i2 != 19) {
            throw new IllegalArgumentException(format);
        }
        throw new IllegalStateException(format);
    }

    static {
        PropertyDescriptorImpl createErrorProperty = createErrorProperty();
        ERROR_PROPERTY = createErrorProperty;
        ERROR_PROPERTY_GROUP = Collections.singleton(createErrorProperty);
    }

    @NotNull
    public static ClassDescriptor createErrorClass(@NotNull String str) {
        if (str == null) {
            $$$reportNull$$$0(1);
        }
        return new ErrorClassDescriptor(Name.special("<ERROR CLASS: " + str + ">"));
    }

    /* JADX INFO: Access modifiers changed from: private */
    @NotNull
    public static SimpleFunctionDescriptor createErrorFunction(@NotNull ErrorScope errorScope) {
        if (errorScope == null) {
            $$$reportNull$$$0(5);
        }
        ErrorSimpleFunctionDescriptorImpl errorSimpleFunctionDescriptorImpl = new ErrorSimpleFunctionDescriptorImpl(ERROR_CLASS, errorScope);
        errorSimpleFunctionDescriptorImpl.initialize((ReceiverParameterDescriptor) null, (ReceiverParameterDescriptor) null, Collections.emptyList(), Collections.emptyList(), (KotlinType) createErrorType("<ERROR FUNCTION RETURN TYPE>"), Modality.OPEN, DescriptorVisibilities.PUBLIC);
        return errorSimpleFunctionDescriptorImpl;
    }

    @NotNull
    private static PropertyDescriptorImpl createErrorProperty() {
        PropertyDescriptorImpl create = PropertyDescriptorImpl.create(ERROR_CLASS, Annotations.Companion.getEMPTY(), Modality.OPEN, DescriptorVisibilities.PUBLIC, true, Name.special("<ERROR PROPERTY>"), CallableMemberDescriptor.Kind.DECLARATION, SourceElement.NO_SOURCE, false, false, false, false, false, false);
        create.setType(ERROR_PROPERTY_TYPE, Collections.emptyList(), null, null);
        return create;
    }

    @NotNull
    public static MemberScope createErrorScope(@NotNull String str) {
        if (str == null) {
            $$$reportNull$$$0(2);
        }
        return createErrorScope(str, false);
    }

    @NotNull
    public static SimpleType createErrorType(@NotNull String str) {
        if (str == null) {
            $$$reportNull$$$0(7);
        }
        return createErrorTypeWithArguments(str, Collections.emptyList());
    }

    @NotNull
    public static TypeConstructor createErrorTypeConstructor(@NotNull String str) {
        if (str == null) {
            $$$reportNull$$$0(15);
        }
        return createErrorTypeConstructorWithCustomDebugName(C1499a.m639y("[ERROR : ", str, "]"), ERROR_CLASS);
    }

    @NotNull
    public static TypeConstructor createErrorTypeConstructorWithCustomDebugName(@NotNull String str) {
        if (str == null) {
            $$$reportNull$$$0(16);
        }
        return createErrorTypeConstructorWithCustomDebugName(str, ERROR_CLASS);
    }

    @NotNull
    public static SimpleType createErrorTypeWithArguments(@NotNull String str, @NotNull List<TypeProjection> list) {
        if (str == null) {
            $$$reportNull$$$0(11);
        }
        if (list == null) {
            $$$reportNull$$$0(12);
        }
        return new ErrorType(createErrorTypeConstructor(str), createErrorScope(str), list, false);
    }

    @NotNull
    public static SimpleType createErrorTypeWithCustomConstructor(@NotNull String str, @NotNull TypeConstructor typeConstructor) {
        if (str == null) {
            $$$reportNull$$$0(9);
        }
        if (typeConstructor == null) {
            $$$reportNull$$$0(10);
        }
        return new ErrorType(typeConstructor, createErrorScope(str));
    }

    @NotNull
    public static SimpleType createErrorTypeWithCustomDebugName(@NotNull String str) {
        if (str == null) {
            $$$reportNull$$$0(8);
        }
        return createErrorTypeWithCustomConstructor(str, createErrorTypeConstructorWithCustomDebugName(str));
    }

    @NotNull
    public static ModuleDescriptor getErrorModule() {
        ModuleDescriptor moduleDescriptor = ERROR_MODULE;
        if (moduleDescriptor == null) {
            $$$reportNull$$$0(19);
        }
        return moduleDescriptor;
    }

    public static boolean isError(@Nullable DeclarationDescriptor declarationDescriptor) {
        if (declarationDescriptor == null) {
            return false;
        }
        return isErrorClass(declarationDescriptor) || isErrorClass(declarationDescriptor.getContainingDeclaration()) || declarationDescriptor == ERROR_MODULE;
    }

    private static boolean isErrorClass(@Nullable DeclarationDescriptor declarationDescriptor) {
        return declarationDescriptor instanceof ErrorClassDescriptor;
    }

    public static boolean isUninferredParameter(@Nullable KotlinType kotlinType) {
        return kotlinType != null && (kotlinType.getConstructor() instanceof UninferredParameterTypeConstructor);
    }

    @NotNull
    public static MemberScope createErrorScope(@NotNull String str, boolean z) {
        if (str == null) {
            $$$reportNull$$$0(3);
        }
        return z ? new ThrowingScope(str) : new ErrorScope(str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    @NotNull
    public static TypeConstructor createErrorTypeConstructorWithCustomDebugName(@NotNull final String str, @NotNull final ErrorClassDescriptor errorClassDescriptor) {
        if (str == null) {
            $$$reportNull$$$0(17);
        }
        if (errorClassDescriptor == null) {
            $$$reportNull$$$0(18);
        }
        return new TypeConstructor() { // from class: kotlin.reflect.jvm.internal.impl.types.ErrorUtils.2
            private static /* synthetic */ void $$$reportNull$$$0(int i2) {
                String str2 = i2 != 3 ? "@NotNull method %s.%s must not return null" : "Argument for @NotNull parameter '%s' of %s.%s must not be null";
                Object[] objArr = new Object[i2 != 3 ? 2 : 3];
                if (i2 != 3) {
                    objArr[0] = "kotlin/reflect/jvm/internal/impl/types/ErrorUtils$2";
                } else {
                    objArr[0] = "kotlinTypeRefiner";
                }
                if (i2 == 1) {
                    objArr[1] = "getSupertypes";
                } else if (i2 == 2) {
                    objArr[1] = "getBuiltIns";
                } else if (i2 == 3) {
                    objArr[1] = "kotlin/reflect/jvm/internal/impl/types/ErrorUtils$2";
                } else if (i2 != 4) {
                    objArr[1] = "getParameters";
                } else {
                    objArr[1] = "refine";
                }
                if (i2 == 3) {
                    objArr[2] = "refine";
                }
                String format = String.format(str2, objArr);
                if (i2 == 3) {
                    throw new IllegalArgumentException(format);
                }
            }

            @Override // kotlin.reflect.jvm.internal.impl.types.TypeConstructor
            @NotNull
            public KotlinBuiltIns getBuiltIns() {
                DefaultBuiltIns defaultBuiltIns = DefaultBuiltIns.getInstance();
                if (defaultBuiltIns == null) {
                    $$$reportNull$$$0(2);
                }
                return defaultBuiltIns;
            }

            @Override // kotlin.reflect.jvm.internal.impl.types.TypeConstructor
            @Nullable
            /* renamed from: getDeclarationDescriptor */
            public ClassifierDescriptor mo7311getDeclarationDescriptor() {
                return ErrorClassDescriptor.this;
            }

            @Override // kotlin.reflect.jvm.internal.impl.types.TypeConstructor
            @NotNull
            public List<TypeParameterDescriptor> getParameters() {
                List<TypeParameterDescriptor> emptyList = CollectionsKt__CollectionsKt.emptyList();
                if (emptyList == null) {
                    $$$reportNull$$$0(0);
                }
                return emptyList;
            }

            @Override // kotlin.reflect.jvm.internal.impl.types.TypeConstructor
            @NotNull
            /* renamed from: getSupertypes */
            public Collection<KotlinType> mo7312getSupertypes() {
                List emptyList = CollectionsKt__CollectionsKt.emptyList();
                if (emptyList == null) {
                    $$$reportNull$$$0(1);
                }
                return emptyList;
            }

            @Override // kotlin.reflect.jvm.internal.impl.types.TypeConstructor
            public boolean isDenotable() {
                return false;
            }

            @Override // kotlin.reflect.jvm.internal.impl.types.TypeConstructor
            @NotNull
            public TypeConstructor refine(@NotNull KotlinTypeRefiner kotlinTypeRefiner) {
                if (kotlinTypeRefiner == null) {
                    $$$reportNull$$$0(3);
                }
                return this;
            }

            public String toString() {
                return str;
            }
        };
    }
}
