---
layout: single
title: "Testing navigation iOS"
author_profile: true
permalink: /:categories/:title/
tags: ios development unittests
---

Note: This article assumes that you are familiar with 
[Coordinator pattern](https://www.hackingwithswift.com/articles/71/how-to-use-the-coordinator-pattern-in-ios-apps)
and
[SwiftyMocky or other mock solution](https://github.com/MakeAWishFoundation/SwiftyMocky).

Testing navigation between screens may appear hard when it is not prepared for Unit Testing. 
FlowController or Coordinator are patterns to manage the navigation between screens, that extract navigation from ViewController.
But often it creates the whole screen and setups screen properties like ViewController, ViewModel, etc. to display. 
This makes it hard to test and it can break the single responsibility principle. 

Let’s look at a commonly used FlowController logic:

```swift
func showLoginScreen() {
    let viewModel = LoginViewModel(
        service1: service1,
        service2: service2,
        store: store,
        actionHandler: { [weak self] action in
            switch action {
            case .loggedIn:
                self?.onLoggedIn()
            case let .alert(model):
                self?.showAlert(model: model)
            }
        }
    )
    let viewController = LoginViewController(viewModel: viewModel)
    viewController.delegate = viewModel
    navigationController.setViewControllers([viewController], animated: true)
}
```

Above function requires multiple dependencies, that are not part of navigation. 
They will bloat the FlowController with instances, that could be moved to another structure.
If we will have to pass additional dependency to ViewModel, it will require change of FlowController, 
which is not ideal cause you are not modifing navigation, but just passing another param to screen presented by FlowController.

If we would like to test it, we pottencially could check, if passed ViewController is type of LoginViewController,
but we can't mock passed ViewController and it would be hard to extract the action handler passed from FlowController.

# How it can be improved?

Factory could be introduced to create the ViewController and pass the completion handlers, 
without any knowledge how ViewController is being created and what took to initalize it.
In this way, we will be able to only check which navigation controller and factory methods were called.
We don’t need to check if the correct ViewController was created, it is the factory’s responsibility. 
Additionally, it will align the code with the open-close principle because 
we can change the presented ViewController using different factory instances without changing the FlowController. 
The nice thing about this solution is that you can have almost the final version FlowController 
without implementing the Login screen elements, you can create them later and just adjust the Factory without any FlowControllers changes.

✅ Improved code

```swift
func showLoginScreen() {
  let viewController = loginFlowControllerElementsFactory.createLoginViewController(
      actionHandler: { [weak self] action in
          switch action {
          case .loggedIn:
              self?.onLoggedIn()
          case let .alert(model):
              self?.showAlert(model: model)
          }
      }
  )
  navigationController.setViewControllers([viewController], animated: true)
}
```

Code is much more clear and we can easily see what can be tested:
- Check if createLoginViewController has been called
- Check actions results on actionHandler call
- Check if navigationController called setViewControllers with passed viewController from factory

# How can we mock the UINavigationController?

You will just need a protocol to cover UINavigationController methods and conform to it, like:

```swift
/// Wrapper for UINavigationController methods used in FlowController
// sourcery: AutoMockable
protocol NavigationController: AnyObject {
    var viewControllers: [UIViewController] { get set }
    var modalPresentationStyle: UIModalPresentationStyle { get set }

    func present(_ viewControllerToPresent: UIViewController, animated flag: Bool, completion: (() -> Void)?)
    func pushViewController(_ viewController: UIViewController, animated: Bool)
    func present(navigationController: NavigationController, animated flag: Bool, completion: (() -> Void)?)
    func push(navigationController: NavigationController, animated: Bool)
    func setViewControllers(_ viewControllers: [UIViewController], animated: Bool)
    func dismiss(animated flag: Bool, completion: (() -> Void)?)

    @discardableResult func popToViewController(_ viewController: UIViewController, animated: Bool) -> [UIViewController]?
}

// MARK: - UINavigationController + NavigationController

extension UINavigationController: NavigationController {
    func present(navigationController: NavigationController, animated flag: Bool, completion: (() -> Void)?) {
        guard let viewControllerToPresent = navigationController as? UIViewController else {
            // Cannot present NavigationController that does not conform to UIViewController
            return
        }
        present(viewControllerToPresent, animated: flag, completion: completion)
    }

    func push(navigationController: NavigationController, animated: Bool) {
        guard let viewController = navigationController as? UIViewController else {
            // Cannot push NavigationController that does not conform to UIViewController
            return
        }
        pushViewController(viewController, animated: animated)
    }
}
```

With it, we can create the mock and verify calls by using a mocking library like SwiftyMocky.

## Testing the code

Simplified code to test if correct factory function was called and navigation controller presented it in correct way will look like:

```swift
loginFlowControllerElementsFactory.verify(.createLoginViewController(actionHandler: .any))
navigationController.verify(
    .setViewControllers(
        .matching { $0.count == 1 && $0.first === loginViewController },
        animated: .value(true)
    )
)
```

# Summary

Do I need it? As always: It depends, because most of the solutions got pross and cons.
We should always choose solutions that gives us more pros and makes our life easier.
If your project require FlowController to be testable, it is a nice way to do it.

Check out prepared [single commit](https://github.com/karolpiateknet/BlogExamples/commit/b382d9bc069f106731255b6953168ceca37d7f70) 
with the FlowController, factory implementation and tests for the whole solution code example.
