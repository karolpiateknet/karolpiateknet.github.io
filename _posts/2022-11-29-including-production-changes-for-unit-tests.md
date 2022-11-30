---
layout: single
title: "Including production changes for Unit Tests"
author_profile: true
permalink: /:categories/:title/
tags: ios development unittests
---

It is expected to change production code to make it testable, but developers tend to do workarounds to just do things instead of do it right.
One such workaround would be to include changes needed only for Unit Tests without benefits
in the production code like changing access modifiers. While it might help you in the short run 
it will not in the long one. It will usually backfire after some time creating bugs or confusing behaviors. 

# Changing access modifier

If you are thinking about changing the private method or variable to make Unit Tests easier, 
you should think if your code does one thing (Single Responsibility principle). 
In my career when I or other developers introduced such changes, it always meant that the class is doing a lot of things 
and it is really hard to test. It might be a great indicator that you should rethink your class and make it easy to test.

# Including equatable conformance

If we add Equatable conformance at the struct definition, we will get implementation wihtout need to implement it, 
Swift will provide default implementation with comparing every element field by itself.
It is a tempting situation to add equatable to structs that need it in UnitTesting to not implement the equal function by yourself.

```swift
struct Model: Equatable {
    let id: String
    let title: String
}
```

However, this implementation will be only created for UnitTests, but also available in the production code, 
if someone will use it they might receive not the expected results. 
Maybe in the production code, you will need a different implementation to just compare the object ID instead of all element fields.
And you will create custom implementation:

```swift
static func == (lhs: Model, rhs: Model) -> Bool {
    return lhs.id == rhs.id
}
```

All tests will pass, because you just limited the scope of the Unit Test and you will just not check if the title is correct.

## How we can approach it differently?

What I would recommend is the generation of the Equatable conformance with the [Sourcery](https://github.com/krzysztofzablocki/Sourcery). 
You can find the AutoEquatable template that is ready to use. It will generate an Equatable comparison code for you, 
including it only in the Test target. You can also adjust the script to your needs and 
[filter out closures](https://github.com/karolpiateknet/BlogExamples/blob/main/BlogExamplesTests/Sourcery/Templates/AutoEquatable.stencil) for example. 

In this approach when adding the Equatable conformance in production code, you will get duplicated Equatable 
conformance compilation warning. If you have the warnings comments configured in your CI flow to be added to Pull Request, 
you will not merge the code without adjusting it. 

```
Conformance of Model to protocol 'Equatable' was already stated in the type's module `App`
```

Thanks to that warning you will know that something has been changed and maybe Unit Tests should be adjusted.

In my opinion, it is better to use the Sourcery for Equatable conformance only in Unit Tests, because:
- If you are changing the Equatable implementation, you are sure that you will not break the Production code
- We don’t introduce changes only needed by Unit Tests in production code
- Equatable is only visible in the Unit Tests module
- We get a warning when adding the conformance in production code and it is also added in Unit Tests
- We can automatically filter closures comparison from objects
- In cases where we will have to add Equatable conformance manually, previously defined models in the production target will require to add this implementation also in the production target

You can check out [how I added AutoEquatable in my BlogExample project](https://github.com/karolpiateknet/BlogExamples/commit/5f13cbe10ae5ed2556e0032bcd44f40b9d3ec8ba).

# Providing default values

It is a similar story to Equatable conformance, it will introduce confusion when used because
other developers will think that it is the value that should be used in the production code, but it might not be. 
So changing it, might require asking people why this default value is added here, maybe it should be always used?. 

Instead of adding default values in production code, you can add an extension with a function to create object with defined default params.

:x: Don’t
```swift
struct Model {
    init(x: Int = 1, y: Int = 2) {
        // Implementation
    }
}
```

✅ Do
```swift
// In Unit tests target
extension Model {
    func create(x: Int = 1, y: Int = 2) -> Model { … }
}
```

But of course, you should use default values, if it makes things easier, just don’t do it for Unit Tests.

Propably it could be also automated using Sourcery.

# Summary

Before changing your production code to fit your Unit Tests needs, think if your production 
follows SOLID principles and if is it the right way to go. Maybe it will introduce some issues in the future, which it would be best to avoid.

