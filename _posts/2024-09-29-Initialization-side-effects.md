---
layout: single
title: "Initialization side effects"
author_profile: true
permalink: /:categories/:title/
tags: ios development goodpractices
---

It might be tempting sometimes to fetch data inside an initializer, but is it a reliable solution? What price do we pay when fetching data inside the initializer? 

In this article, we'll explore why fetching data in initializers is a bad practice and how it can impact your codebase.

# The Role of Initializers

“Initialization is the process of preparing an instance of a class, structure, or enumeration for use. This process involves setting an initial value 
for each stored property on that instance and performing any other setup or initialization that’s required before the new instance is ready for use.” ~ [Swift documentation](https://docs.swift.org/swift-book/documentation/the-swift-programming-language/initialization/)

So the purpose is to make an instance ready to work with.

You now need to ask the question: Is the instance ready to work with when the data is fetched, or when the class responsible for fetching data is set?

In my opinion, fetching network data breaks the initializer definition and also violates the single responsibility principle, as we not only initialize the instance but also perform other actions.

# Code example

Let's analyze a ViewModel class as an example:

```swift
final class ViewModel {


    var data: Data


    let fetchNetworkDataInteractor: FetchNetworkDataInteractorProtocol
    // ...


    init(fetchNetworkDataInteractor: FetchNetworkDataInteractorProtocol) {
        self.fetchNetworkDataInteractor = fetchNetworkDataInteractor
        fetchNetworkDataInteractor
            .fetchData()
            .subscribe(onSuccess: {
                self.data = $0
            })
            .disposed(by: disposeBag)
    }


    func fetchData() {
        fetchNetworkDataInteractor
            .fetchData()
            .subscribe(onSuccess: {
                self.data = $0
            })
            .disposed(by: disposeBag)
    }


    func buttonClicked() {
        analytics.trackDidTapButton()
    }
}
```

In this example, the ViewModel fetches data during initialization. While this might in some cases seem like a good idea to get data earlier, it comes with a price.

# Potential for Bugs and unexpected Behavior

Initializing with side effects can lead to hard-to-detect bugs.

For example, Navigation Issues: If the data fetch triggers a navigation action before the screen is fully presented, the app might navigate unexpectedly or get stuck on the current screen because the action was done before the View was presented on the Navigation Controller.

As a result, we could have the wrong view presented to the user or get stuck on the current screen if a navigation action is done before presenting the correct screen.

# Performance and Optimization Issues

Fetching data in init might also delay initialization, which might impact user experience because the screen could be frozen while the ViewModel is initializing.

# Testing Complications

When you have side effects in your initializers, testing becomes more complex:

- Mocking Data: To test any method in the ViewModel, you must provide mocked data for the initializer's data fetch, even if the test doesn't concern the fetched data.
- Unintended Calls: Testing methods like fetchData() can result in multiple calls to the fetchNetworkDataInteractor, since one call happens during initialization and another during the method execution.
- Resetting Mocks: You may need to reset or reconfigure your mocks between tests to prevent unintended interactions, adding extra overhead to your testing process.

# Conclusion

As we saw, having side effects inside the initializer, like fetching data, can cause many issues and make testing harder. By keeping initializers free of side effects and handling data fetching separately, you can write cleaner, more maintainable code.
Remember, the goal is to make your initializers solely responsible for setting up the object's initial state without reaching out to external systems or causing side effects.

