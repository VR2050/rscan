package kotlin.reflect.jvm.internal.impl.descriptors;

/* loaded from: classes.dex */
public interface DeclarationDescriptorVisitor<R, D> {
    R visitClassDescriptor(ClassDescriptor classDescriptor, D d2);

    R visitConstructorDescriptor(ConstructorDescriptor constructorDescriptor, D d2);

    R visitFunctionDescriptor(FunctionDescriptor functionDescriptor, D d2);

    R visitModuleDeclaration(ModuleDescriptor moduleDescriptor, D d2);

    R visitPackageFragmentDescriptor(PackageFragmentDescriptor packageFragmentDescriptor, D d2);

    R visitPackageViewDescriptor(PackageViewDescriptor packageViewDescriptor, D d2);

    R visitPropertyDescriptor(PropertyDescriptor propertyDescriptor, D d2);

    R visitPropertyGetterDescriptor(PropertyGetterDescriptor propertyGetterDescriptor, D d2);

    R visitPropertySetterDescriptor(PropertySetterDescriptor propertySetterDescriptor, D d2);

    R visitReceiverParameterDescriptor(ReceiverParameterDescriptor receiverParameterDescriptor, D d2);

    R visitTypeAliasDescriptor(TypeAliasDescriptor typeAliasDescriptor, D d2);

    R visitTypeParameterDescriptor(TypeParameterDescriptor typeParameterDescriptor, D d2);

    R visitValueParameterDescriptor(ValueParameterDescriptor valueParameterDescriptor, D d2);
}
