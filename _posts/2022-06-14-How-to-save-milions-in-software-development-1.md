---
layout: single
title: How to save millions in software development: part 1
author_profile: true
permalink: /:categories/:title/
tags: scrum development
---

In every industry some things could improve the workflow in terms of accuracy, speed, or decreasing the amount of unnecessary work. If a developer wastes 20 minutes daily with a $60 per hour rate, it is:

  - $20 daily
  - $400 monthly
  - $4800 yearly

Taking that into account, the company which employs 1 000 developers would lose $4.8 mln yearly. In this blog post, I will try to raise a yellow flag at some things in software development, that in my opinion are unnecessarily expensive and could be improved.

Remember that many 1% improvements can make a big difference in the long run: [https://jamesclear.com/marginal-gains](https://jamesclear.com/marginal-gains)

# Tickets

A Big part of software development is the creation of requirements and tickets. It can be done in many ways and it has a huge impact on work performance. Poorly defined tickets or requirements will result in slow performance and frustration or memes like this:

![Swing three](/assets/images/posts/How-to-save-millions/swing-tree.jpeg) 

Image source: https://imgur.com/3O2kOG4

Remember that ambiguity on the refinement level is normal, but when a ticket is in the scrum sprint, I believe that it should be defined as detailed as possible to save time, which could be spent more productively by reading about new exciting tech solutions.

## Ticket with only a title

**Ticket title**: User can remove article

Such unclear ticket comes with quite a few questions, to clarify things:

    - On which screen should User be able to remove the article? Maybe an article could be removed with a swipe gesture or with the remove button on the details screen. 
    - Should I implement a confirmation alert?
    - Where can I find the design?

As you can see, a simple ticket to remove an article can cause a lot of confusion. If the ticket were more complex, the list of questions would be much, much longer. Working with such tickets will generally result in additional work unless you’re the one who created the ticket and you remember all the details about it.

In the worst-case scenario, implementation would look like this:

  1. Thinking about what the author had in mind? 
  2. Thinking "am I an idiot, that I do not understand it?"
  3. Searching for the answers in documentation or references
  4. Searching for the design
  5. Asking people for needed information will not only disturb their work but in some cases can block your work on the current ticket, as you sometime may wait a couple of hours or even days for the answer. While changing the work context to a different ticket might be expensive.
  6. Then you realized that the ticket is blocked by another dependency and your team needs to fix it first. Because of not clear requirements you might still implement things incorrectly and have a ping pong with QA. Then adjusting implementation to correct behavior will require:
        - fixing the issue
        - creating a pull request
        - running CI build
        - doing code review
        - fixing code review comments
        - releasing a new build for QA

As you can see, the list can get really long. Poor ticket description can cause a simple task to become, sometimes even a couple-days long, unpleasant, stressful journey.

## Tickets with many references

While it may contain all the necessary knowledge to complete the task, it will take more time to go through all of the links and filer all gathered information to find ones that are related to the ticket. When you could just add those pieces of information on refinement.

## What should a great ticket look like?

Now, having in mind the previously described tickets, what would you say about the ticket that looks like this:

**Title**: User can remove an article from article details screen

### 📖 User Story

As a user I would like to be able to remove the article on the details screen.

### Why created/needed? ( might be skipped, but it is a nice addition for technical tickets, to justify them to business )
 
This feature was requested by many users in the feedback form.

### Description:

ButtonView could be used to match the design with Style.negative option.

### Link to design:

https://www.figma.com 

### QA tips:

Creating articles requires a special admin account using “Admin account” from 1Password.

### ✅ Acceptance criteria:

Dev ✅  / :x: | QA ✅  / :x: | Requirement | Comment
:---: | :---: | --- | --- 
✅ | | Delete button is present on the article details screen. | 
:x: | | It has the correct design | Link to design.
 | | After tapping the delete button confirmation alert is displayed. |
 | | Delete confirmation alert has correct design | Link to design.
 | | On delete confirmation alert: Cancel button dismisses alert and articles details are visible. | 
 | | On delete confirmation alert: Remove button dismiss alert and close article details screen. |
 | | After article removal: Removed article is not visible on the articles list. |
 | | All texts are localized |

It is a huge difference, right? A little more time put into the ticket creation can help you to save it later on. For me writing detailed tickets also force me to analyze the ticket in-depth and clarify things that I’m not sure about or discover some blockers or dependencies, that should be done first.

Also remember that you will not gather 100% requirements all the time, before implementation. This is perfectly fine because the goal is to provide as many details as possible.

# How to measure if it paid off?

We want to optimize our work, not increase it. To do that we should set some goals, which we would like to achieve and observe some metrics:

    - The number of unknown things in tickets, that come up during development has been decreased
    - The Number of bugs has been decreased
    - QA team has the higher capacity
    - Average number of story points done by team has increased
    - Precision of the planning has been increased, due to more clear requirements
    - Happiness index has increased due to less frustration about ambiguous tickets

This approach might not work in every case. That's why you should define clear goals that you would like to achieve and measure their progress.

#Summary

In my experience, well-described tickets save a lot of time and frustration. Since when you put a ticket into the sprint, you should know what should be done in the scope of it, it will also help you define clear requirements. Even if you are the one, who is responsible for creating the ticket, you should not rely solely on your memory. There is always a possibility that you will miss something important, and the circle of "this is supposed to be a simple task" repeats.

While creating such tickets in the past, I also spotted that detailed acceptance criteria resulted in a smaller number of bugs. I hope these tips will help you speed up development and limit the number of bugs.
